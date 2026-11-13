use super::*;
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{AeadInPlace, KeyInit},
};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use vnlens_core::Secret;
use vnlens_io::BinaryWriter;
const PARAMS: [u8; 22] = [
    2, 0, 6, 5, 1, 4, 3, 7, 1, 5, 3, 2, 0, 4, 1, 0, 2, 1, 0xe2, 2, 0x83, 2,
];
fn u16v(out: &mut Vec<u8>, v: u16) {
    let p = out.len();
    out.resize(p + 2, 0);
    BinaryWriter::u16_le(v, &mut out[p..]);
}
fn u32v(out: &mut Vec<u8>, v: u32) {
    let p = out.len();
    out.resize(p + 4, 0);
    BinaryWriter::u32_le(v, &mut out[p..]);
}
fn u64v(out: &mut Vec<u8>, v: u64) {
    let p = out.len();
    out.resize(p + 8, 0);
    BinaryWriter::u64_le(v, &mut out[p..]);
}
fn encoded_chunk(tag: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    u64v(&mut out, b.len() as u64);
    out.extend(b);
    out
}
fn array(out: &mut Vec<u8>, n: u32) {
    out.push(0x81);
    let p = out.len();
    out.resize(p + 4, 0);
    BinaryWriter::u32_be(n, &mut out[p..]);
}
fn octets(out: &mut Vec<u8>, n: u8) {
    out.extend([3, 0, 0, 0, n]);
    out.resize(out.len() + usize::from(n), 0);
}
fn integer(out: &mut Vec<u8>, n: u64) {
    out.push(4);
    let p = out.len();
    out.resize(p + 8, 0);
    BinaryWriter::u64_be(n, &mut out[p..]);
}
fn zip(b: &[u8]) -> Result<Vec<u8>> {
    let mut w = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    w.write_all(b)?;
    Ok(w.finish()?)
}
fn options() -> ArchiveOptions {
    let mut opts = ArchiveOptions::default();
    opts.numbers.insert("hxv4", 1);
    for (name, bytes) in [
        ("hxv4_params", PARAMS.as_slice()),
        ("hxv4_index", &[3; 32]),
        ("hxv4_nonce0", &[7; 24]),
        ("hxv4_nonce1", &[9; 24]),
        ("hxv4_table", &[0; 4096]),
    ] {
        opts.keys.insert(name, Secret::new(bytes));
    }
    opts
}
fn record(
    name: &str,
    flags: u32,
    size: u64,
    segments: &[(u32, u64, u64, u64)],
    adler: u32,
) -> Vec<u8> {
    let mut info = Vec::new();
    u32v(&mut info, flags);
    u64v(&mut info, size);
    u64v(&mut info, segments.iter().map(|s| s.3).sum());
    u16v(&mut info, name.encode_utf16().count() as u16);
    for w in name.encode_utf16() {
        u16v(&mut info, w);
    }
    let mut seg = Vec::new();
    for &(flags, offset, size, stored) in segments {
        u32v(&mut seg, flags);
        u64v(&mut seg, offset);
        u64v(&mut seg, size);
        u64v(&mut seg, stored);
    }
    let mut body = encoded_chunk(b"info", &info);
    body.extend(encoded_chunk(b"segm", &seg));
    let mut sum = Vec::new();
    u32v(&mut sum, adler);
    body.extend(encoded_chunk(b"adlr", &sum));
    encoded_chunk(b"File", &body)
}
struct Sample {
    path: PathBuf,
    bytes: Vec<u8>,
    special: usize,
    index: usize,
}
impl Drop for Sample {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
impl Sample {
    fn new(slot: u16) -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Error::Unsupported(e.to_string()))?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "vnlens-hxv4-{}-{stamp}-{}.xp3",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut bytes = MAGIC.to_vec();
        u64v(&mut bytes, 0);
        // Index chaining starts with an empty continuation block.
        let chain = bytes.len();
        bytes.push(0x80);
        u64v(&mut bytes, 0);
        u64v(&mut bytes, 0);
        let filter =
            Filter::from_params_and_table(&PARAMS, &[0; 1024]).map_err(Error::Unsupported)?;
        let plain = b"header spanning multiple independently compressed segments";
        let mut cipher = plain.to_vec();
        filter.apply_entry(0x123456789abcdef0, 1, 0, &mut cipher);
        let mut segments = Vec::new();
        for (i, part) in [&cipher[..7], &cipher[7..31], &cipher[31..]]
            .iter()
            .enumerate()
        {
            let data = if i == 1 { zip(part)? } else { part.to_vec() };
            segments.push((
                u32::from(i == 1),
                bytes.len() as u64,
                part.len() as u64,
                data.len() as u64,
            ));
            bytes.extend(data);
        }
        let first = record(
            "倁",
            0x80000000,
            plain.len() as u64,
            &segments,
            adler32::checksum(plain),
        );
        let bad_offset = bytes.len() as u64;
        bytes.extend([0, 1, 2]);
        let bad = record("倂", 0x80000000, 9, &[(1, bad_offset, 9, 3)], 0);
        let startup_offset = bytes.len() as u64;
        bytes.extend(b"boot");
        let startup = record(
            "startup.tjs",
            0x80000000,
            4,
            &[(0, startup_offset, 4, 4)],
            adler32::checksum(b"boot"),
        );
        let mut table = Vec::new();
        array(&mut table, 4);
        octets(&mut table, 8);
        let end = table.len();
        table[end - 8..].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]);
        array(&mut table, 4);
        for (id, hash) in [(1, 0xab), (2, 0xcd)] {
            octets(&mut table, 32);
            let end = table.len();
            table[end - 32..].fill(hash);
            array(&mut table, 2);
            integer(&mut table, (1 << 32) | id);
            integer(&mut table, 0x123456789abcdef0);
        }
        octets(&mut table, 8);
        let end = table.len();
        table[end - 8..].fill(0x34);
        array(&mut table, 4);
        // A second path aliases the first physical entry. A foreign archive
        // slot reuses its lookup id with an unrelated key and filename hash.
        for (slot, hash, key) in [(0, 0xab, 0x123456789abcdef0), (1, 0xef, 7)] {
            octets(&mut table, 32);
            let end = table.len();
            table[end - 32..].fill(hash);
            array(&mut table, 2);
            integer(&mut table, (slot << 48) | (1 << 32) | 1);
            integer(&mut table, key);
        }
        let mut sealed = Vec::new();
        u32v(&mut sealed, table.len() as u32);
        sealed.extend(zip(&table)?);
        let nonce = if slot == 0 { [7; 24] } else { [9; 24] };
        let tag = XChaCha20Poly1305::new((&[3; 32]).into())
            .encrypt_in_place_detached((&nonce).into(), b"", &mut sealed)
            .map_err(|_| Error::Unsupported("Fixture encryption failed".into()))?;
        let special = bytes.len();
        bytes.extend(tag);
        bytes.extend(&sealed);
        let mut d = Vec::new();
        u64v(&mut d, special as u64);
        u32v(&mut d, (sealed.len() + 16) as u32);
        u16v(&mut d, slot);
        let mut index = encoded_chunk(b"Hxv4", &d);
        index.extend(first);
        index.extend(bad);
        index.extend(startup);
        let index_at = bytes.len();
        bytes.push(1);
        let compressed = zip(&index)?;
        u64v(&mut bytes, compressed.len() as u64);
        u64v(&mut bytes, index.len() as u64);
        bytes.extend(compressed);
        BinaryWriter::u64_le(chain as u64, &mut bytes[11..]);
        BinaryWriter::u64_le(index_at as u64, &mut bytes[chain + 9..]);
        Ok(Self {
            path,
            bytes,
            special,
            index: index_at,
        })
    }
    fn open(&self) -> Result<Box<dyn Archive>> {
        fs::write(&self.path, &self.bytes)?;
        Xp3.open(&Arc::new(ArcView::open(&self.path)?), &options())
    }
}
#[test]
fn chained_indices_both_nonces_and_segment_offsets_are_lazy() -> Result<()> {
    for slot in [0, 1] {
        let sample = Sample::new(slot)?;
        let archive = sample.open()?;
        assert_eq!(archive.entries().len(), 4);
        assert_eq!(
            &*archive.open_entry(&archive.entries()[0])?,
            b"header spanning multiple independently compressed segments"
        );
        assert_eq!(
            &*archive.open_entry(&archive.entries()[1])?,
            b"header spanning multiple independently compressed segments"
        );
        assert_eq!(
            archive.open_entry_raw(&archive.entries()[0])?,
            archive.open_entry_raw(&archive.entries()[1])?
        );
        assert!(archive.open_entry(&archive.entries()[2]).is_err());
        assert_eq!(&*archive.open_entry_raw(&archive.entries()[2])?, &[0, 1, 2]);
        assert_eq!(&*archive.open_entry(&archive.entries()[3])?, b"boot");
        assert!(matches!(
            archive.open_entry_raw(&archive.entries()[3])?,
            Cow::Borrowed(_)
        ));
        assert_eq!(
            archive.entries()[0].name,
            format!("1234567890ABCDEF/{}", "AB".repeat(32))
        );
        assert_eq!(
            archive.entries()[1].name,
            format!("3434343434343434/{}", "AB".repeat(32))
        );
        assert_eq!(
            archive.entries()[2].name,
            format!("1234567890ABCDEF/{}", "CD".repeat(32))
        );
        assert_eq!(archive.entries()[3].name, "startup.tjs");
        assert!(archive.virtual_paths()?.is_empty());
    }
    Ok(())
}

#[test]
fn repeated_paths_preserve_entries_and_select_their_storage() -> Result<()> {
    let mut sample = Sample::new(0)?;
    let mut bytes = MAGIC.to_vec();
    u64v(&mut bytes, 0);
    let first = bytes.len() as u64;
    bytes.extend(b"one");
    let second = bytes.len() as u64;
    bytes.extend(b"two");
    let mut index = Vec::new();
    for (offset, text) in [(first, b"one"), (first, b"one"), (second, b"two")] {
        index.extend(record(
            "same.bin",
            0,
            3,
            &[(0, offset, 3, 3)],
            adler32::checksum(text),
        ));
    }
    let at = bytes.len() as u64;
    bytes.push(0);
    u64v(&mut bytes, index.len() as u64);
    bytes.extend(index);
    BinaryWriter::u64_le(at, &mut bytes[11..]);
    sample.bytes = bytes;
    let archive = sample.open()?;
    assert_eq!(archive.entries().len(), 3);
    for (entry, expected) in archive.entries().iter().zip([b"one", b"one", b"two"]) {
        assert_eq!(entry.name, "same.bin");
        assert_eq!(&*archive.open_entry(entry)?, expected);
        assert_eq!(&*archive.open_entry_raw(entry)?, expected);
        let mut foreign = entry.clone();
        foreign.offset += 1;
        assert!(archive.open_entry(&foreign).is_err());
    }
    Ok(())
}
#[test]
fn rejects_modified_authentication_cycles_truncation_and_segment_overflow() -> Result<()> {
    let mut sample = Sample::new(0)?;
    sample.bytes[sample.special] ^= 1;
    assert!(matches!(sample.open(), Err(Error::Corrupt { .. })));
    sample.bytes[sample.special] ^= 1;
    BinaryWriter::u64_le(19, &mut sample.bytes[28..]);
    assert!(matches!(sample.open(), Err(Error::Corrupt { .. })));
    BinaryWriter::u64_le(sample.index as u64, &mut sample.bytes[28..]);
    for len in [0, 10, 18, sample.bytes.len() - 1] {
        fs::write(&sample.path, &sample.bytes[..len])?;
        assert!(
            Xp3.open(&Arc::new(ArcView::open(&sample.path)?), &options())
                .is_err()
        );
    }
    let file = record("normal", 0, 2, &[(0, u64::MAX, 2, 2)], 1);
    assert!(matches!(parse_file(&file[12..], 1024), Err(Error::Io(_))));
    Ok(())
}
#[test]
fn special_counts_signed_keys_and_deep_extra_metadata() -> Result<()> {
    let mut table = Vec::new();
    array(&mut table, 2);
    octets(&mut table, 8);
    array(&mut table, 2);
    octets(&mut table, 32);
    array(&mut table, 3);
    integer(&mut table, 0x8001000100000007);
    integer(&mut table, u64::MAX);
    for _ in 0..1024 {
        array(&mut table, 1);
    }
    table.push(0);
    let index = special::read(&table)?;
    let binding = &index[&(0x8001, "倇".into())][0];
    assert_eq!(binding.filter, (u64::MAX, 1));
    assert_eq!(
        binding.path,
        format!("0000000000000000/{}", "00".repeat(32))
    );
    table.pop();
    assert!(matches!(special::read(&table), Err(Error::Io(_))));
    assert!(special::read(&[0x81, 0xff, 0xff, 0xff, 0xff]).is_err());
    assert!(special::read(&[0x81, 0, 0, 0, 1]).is_err());
    Ok(())
}

#[test]
fn plain_xp3_is_shared_and_hxv4_requires_explicit_engine_option() -> Result<()> {
    let sample = Sample::new(0)?;
    fs::write(&sample.path, &sample.bytes)?;
    let mut disabled = options();
    disabled.numbers.remove("hxv4");
    assert!(matches!(
        Xp3.open(&Arc::new(ArcView::open(&sample.path)?), &disabled),
        Err(Error::UnknownScheme(_))
    ));
    let data = b"plain";
    let index = record(
        "original name.txt",
        0,
        5,
        &[(0, 19, 5, 5)],
        adler32::checksum(data),
    );
    let mut bytes = MAGIC.to_vec();
    u64v(&mut bytes, 24);
    bytes.extend(data);
    bytes.push(0);
    u64v(&mut bytes, index.len() as u64);
    bytes.extend(index);
    fs::write(&sample.path, &bytes)?;
    let archive = Xp3.open(
        &Arc::new(ArcView::open(&sample.path)?),
        &ArchiveOptions::default(),
    )?;
    assert_eq!(archive.entries()[0].name, "original name.txt");
    assert_eq!(&*archive.open_entry(&archive.entries()[0])?, data);
    assert!(matches!(
        archive.open_entry(&archive.entries()[0])?,
        Cow::Borrowed(_)
    ));
    Ok(())
}
#[test]
fn recovery_is_explicit_cross_archive_cancellable_and_keeps_unresolved_hashes() -> Result<()> {
    use std::sync::atomic::AtomicBool;
    use vnlens_crypto::hash::hxv4 as hashes;
    fn hashed(dir: &str, name: &str) -> String {
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02X}")).collect::<String>();
        format!(
            "{}/{}",
            hex(&hashes::directory(dir, "xp3hnp")),
            hex(&hashes::filename(name, "xp3hnp"))
        )
    }
    fn write(path: &std::path::Path, entries: &[(String, &[u8])]) -> Result<()> {
        let mut bytes = MAGIC.to_vec();
        u64v(&mut bytes, 0);
        let mut index = Vec::new();
        for (name, data) in entries {
            index.extend(record(
                name,
                0,
                data.len() as u64,
                &[(0, bytes.len() as u64, data.len() as u64, data.len() as u64)],
                adler32::checksum(data),
            ));
            bytes.extend_from_slice(data);
        }
        let offset = bytes.len() as u64;
        BinaryWriter::u64_le(offset, &mut bytes[11..]);
        bytes.push(0);
        u64v(&mut bytes, index.len() as u64);
        bytes.extend(index);
        fs::write(path, bytes)?;
        Ok(())
    }
    let source = Sample::new(0)?;
    let images = Sample::new(0)?;
    let first = hashed("scenario/chapter/", "first.ks");
    let missing = hashed("unknown/", "unreferenced.png");
    write(&source.path,&[(hashed("","startup.tjs"),br#"var a="scenario/"+"chapter/first.ks"; var b="image/bg.png"; var c="prefix"+unknown+"suffix.png"; var actor="actor.stand";"#)])?;
    write(
        &images.path,
        &[
            (first.clone(), b"@image storage=image/bg.png"),
            (hashed("image/", "bg.png"), b"\x89PNG\r\n\x1a\n\0\0"),
            (missing.clone(), b"\0\x01"),
            (hashed("", "bad.ks"), b"\xfe\xfe"),
            (hashed("", "actor.stand"), br#"[%["filename"=>"actor1"]]"#),
            (hashed("", "actor1.txt"), b"#layer_type\tname\tleft\ttop\twidth\theight\ttype\topacity\tvisible\tlayer_id\tgroup_layer_id\tbase\timages\n0\tface\t0\t0\t1\t1\t13\t255\t1\t7\n"),
            (hashed("", "actor1_7.tlg"), b"\0"),
            (hashed("", "actor1_8.tlg"), b"\0"),
        ],
    )?;
    let cancel = AtomicBool::new(false);
    let inputs = [
        (images.path.clone(), ArchiveOptions::default()),
        (source.path.clone(), ArchiveOptions::default()),
    ];
    let mut recovery = NameRecovery::open(&inputs, &cancel)?;
    assert_eq!(recovery.progress().completed, 0);
    let original = Xp3.open(
        &Arc::new(ArcView::open(&images.path)?),
        &ArchiveOptions::default(),
    )?;
    while recovery.step(&cancel)? {}
    let paths = recovery.paths();
    assert_eq!(paths[&images.path][0], "scenario/chapter/first.ks");
    assert_eq!(paths[&images.path][1], "image/bg.png");
    assert_eq!(paths[&images.path][2], missing);
    assert_eq!(paths[&images.path][4], "actor.stand");
    assert_eq!(paths[&images.path][5], "actor1.txt");
    assert_eq!(paths[&images.path][6], "actor1_7.tlg");
    assert_eq!(
        paths[&images.path][7],
        hashed("", "actor1_8.tlg")
            .split_once('/')
            .map(|(_, file)| file)
            .unwrap_or("")
    );
    assert_eq!(original.entries()[0].name, first);
    assert_eq!(recovery.progress().failed, 1);
    assert_eq!(recovery.take_errors().len(), 1);
    assert!(recovery.take_errors().is_empty());
    // Parallel dispatch can precede discovery of a definition's name. Both
    // fresh sessions and partially stepped sessions must reach the same paths.
    for steps in [0, 3] {
        let mut parallel = NameRecovery::open(&inputs, &cancel)?;
        for _ in 0..steps {
            assert!(parallel.step(&cancel)?);
        }
        let mut snapshots = 0;
        let mut live_names = false;
        let mut finished = 0;
        parallel.run(&cancel, |session, done| {
            snapshots += 1;
            let progress = session.progress();
            assert!(progress.completed <= progress.total);
            if done {
                finished += 1;
                assert_eq!(progress.completed, progress.total);
            } else if progress.completed < progress.total {
                live_names |= session.paths()[&images.path][4] == "actor.stand";
            }
        })?;
        assert!(snapshots > 1);
        assert!(live_names);
        assert_eq!(finished, 1);
        assert_eq!(parallel.paths(), paths);
        assert_eq!(parallel.progress().resolved, recovery.progress().resolved);
        assert_eq!(parallel.progress().failed, 1);
        assert_eq!(parallel.take_errors().len(), 1);
        assert!(parallel.take_errors().is_empty());
    }
    let mut interrupted = NameRecovery::open(&inputs, &cancel)?;
    let mut failures = 0;
    assert!(matches!(
        interrupted.run(&cancel, |session, done| {
            assert!(!done);
            failures = session.progress().failed;
            cancel.store(true, Ordering::Relaxed);
        }),
        Err(Error::Cancelled)
    ));
    assert_eq!(interrupted.progress().failed, failures);
    cancel.store(false, Ordering::Relaxed);
    let mut empty = NameRecovery::open(&[], &cancel)?;
    let mut finished = 0;
    empty.run(&cancel, |session, done| {
        assert!(done);
        assert_eq!(session.progress(), NameProgress::default());
        finished += 1;
    })?;
    assert_eq!(finished, 1);
    assert!(matches!(
        recovery.step(&AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    assert!(matches!(
        NameRecovery::open(&[], &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    Ok(())
}
#[test]
fn xor31_segments_plain_entries_and_bad_payloads_remain_lazy() -> Result<()> {
    let plain: Vec<u8> = (0..251).cycle().take(70001).collect();
    let hash = adler32::checksum(&plain);
    let mut cipher = plain.clone();
    vnlens_crypto::cipher::xp3::xor31(hash, 0, &mut cipher);
    let mut bytes = MAGIC.to_vec();
    u64v(&mut bytes, 0);
    let mut segments = Vec::new();
    let mut raw = Vec::new();
    for (part, compressed) in [
        (&cipher[..7], false),
        (&cipher[7..37], false),
        (&cipher[37..], true),
    ] {
        let data = if compressed {
            zip(part)?
        } else {
            part.to_vec()
        };
        segments.push((
            u32::from(compressed),
            bytes.len() as u64,
            part.len() as u64,
            data.len() as u64,
        ));
        bytes.extend(&data);
        raw.extend(data);
    }
    let mut index = record(
        "folder/日本語.bin",
        0x80000000,
        plain.len() as u64,
        &segments,
        hash,
    );
    let offset = bytes.len() as u64;
    bytes.extend(b"plain");
    index.extend(record(
        "plain.txt",
        0,
        5,
        &[(0, offset, 5, 5)],
        adler32::checksum(b"plain"),
    ));
    let offset = bytes.len() as u64;
    bytes.extend([0, 1, 2]);
    index.extend(record("bad.bin", 0x80000000, 8, &[(1, offset, 8, 3)], 1));
    index.extend(record(
        "wrong_checksum.bin",
        0x80000000,
        plain.len() as u64,
        &segments,
        hash ^ 1,
    ));
    let index_at = bytes.len();
    bytes.push(0);
    u64v(&mut bytes, index.len() as u64);
    bytes.extend(index);
    BinaryWriter::u64_le(index_at as u64, &mut bytes[11..]);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Unsupported(e.to_string()))?
        .as_nanos();
    let sample = Sample {
        path: std::env::temp_dir().join(format!("vnlens-xor31-{}-{stamp}.xp3", std::process::id())),
        bytes,
        special: 0,
        index: index_at,
    };
    fs::write(&sample.path, &sample.bytes)?;
    let view = Arc::new(ArcView::open(&sample.path)?);
    assert!(matches!(
        Xp3.open(&view, &ArchiveOptions::default()),
        Err(Error::UnknownScheme(_))
    ));
    let mut options = ArchiveOptions::default();
    options.numbers.insert("xp3_xor31", 1);
    let archive = Xp3Archive::open(&view, &options)?;
    assert_eq!(archive.entries.len(), 4);
    assert_eq!(&*archive.open_entry(&archive.entries[0])?, &plain);
    let source = archive
        .open_entry_source(&archive.entries[0])?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(&*source.read_at(5, 40)?, &plain[5..45]);
    assert_eq!(&*source.read_at(0, 12)?, &plain[..12]);
    let mut reader = source.reader(Arc::new(std::sync::atomic::AtomicBool::new(false)))?;
    let mut streamed = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut streamed)?;
    assert_eq!(&streamed, &plain);
    assert_eq!(&*archive.open_entry_raw(&archive.entries[0])?, &raw);
    assert!(matches!(
        archive.open_entry(&archive.entries[1])?,
        Cow::Borrowed(b"plain")
    ));
    assert!(archive.open_entry(&archive.entries[2]).is_err());
    assert!(matches!(
        archive.open_entry(&archive.entries[3]),
        Err(Error::Corrupt { .. })
    ));
    assert!(matches!(
        archive.read_cancellable(
            &archive.entries[0],
            &std::sync::atomic::AtomicBool::new(true)
        ),
        Err(Error::Cancelled)
    ));
    options.numbers.insert("hxv4", 1);
    assert!(matches!(
        Xp3.open(&view, &options),
        Err(Error::Unsupported(_))
    ));
    Ok(())
}
