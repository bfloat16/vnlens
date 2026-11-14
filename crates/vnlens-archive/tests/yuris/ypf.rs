#![allow(clippy::unwrap_used)]

use super::*;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use vnlens_crypto::checksum::{adler32, crc32};
use vnlens_io::BinaryWriter;

struct TestFile(std::path::PathBuf);
impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn file(bytes: &[u8]) -> TestFile {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "vnlens-ypf-{}-{}-{}.ypf",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, bytes).unwrap();
    TestFile(path)
}
const RECORDS: &[(&str, &[u8], u8)] = &[("bad.ybn", b"x", 1), ("folder/ok.txt", b"hello", 0)];

#[test]
fn engine_selected_snappy_keeps_mount_lazy_and_verifies_each_payload() -> Result<()> {
    let encoded = [9, 8, b'a', b'b', b'c', 9, 3];
    let mut bytes = fixture(&[("voice.ogg", &encoded, 1), ("bad.bin", b"x", 1)]);
    BinaryWriter::u32_le(9, &mut bytes[32 + 5 + "voice.ogg".len() + 2..]);
    let path = file(&bytes);
    let archive = YpfArchive::open(
        Arc::new(ArcView::open(&path.0)?),
        None,
        None,
        Compression::ExternalSnappy,
    )?;
    assert!(archive.script_key.get().is_none());
    assert_eq!(archive.entries().len(), 2);
    assert!(archive.open_entry_source(&archive.entries()[0])?.is_none());
    assert_eq!(&*archive.open_entry(&archive.entries()[0])?, b"abcabcabc");
    assert_eq!(&*archive.open_entry_raw(&archive.entries()[0])?, &encoded);
    assert!(archive.open_entry(&archive.entries()[1]).is_err());
    Ok(())
}

#[test]
fn external_compression_uses_framing_and_does_not_retry_a_damaged_zlib_stream() -> Result<()> {
    let encoded = [120, 156, 203, 72, 205, 201, 201, 7, 0, 6, 44, 2, 21];
    let mut bytes = fixture(&[("hello.txt", &encoded, 1)]);
    BinaryWriter::u32_le(5, &mut bytes[32 + 5 + "hello.txt".len() + 2..]);
    let path = file(&bytes);
    let archive = YpfArchive::open(
        Arc::new(ArcView::open(&path.0)?),
        None,
        None,
        Compression::ExternalSnappy,
    )?;
    assert_eq!(&*archive.open_entry(&archive.entries()[0])?, b"hello");
    let mut damaged = encoded;
    damaged[12] ^= 1;
    let mut bytes = fixture(&[("damaged.txt", &damaged, 1)]);
    BinaryWriter::u32_le(5, &mut bytes[32 + 5 + "damaged.txt".len() + 2..]);
    let path = file(&bytes);
    let archive = YpfArchive::open(
        Arc::new(ArcView::open(&path.0)?),
        None,
        None,
        Compression::ExternalSnappy,
    )?;
    assert!(matches!(
        archive.open_entry(&archive.entries()[0]),
        Err(Error::Corrupt { .. })
    ));
    let mut ambiguous = vec![120, 156];
    ambiguous.extend(std::iter::repeat_n(b'a', 40));
    ambiguous.extend_from_slice(&[0xfe, 1, 0, 0x3e, 1, 0]);
    assert!(vnlens_crypto::compress::snappy::validate(&ambiguous, 120).is_ok());
    let mut bytes = fixture(&[("ambiguous.txt", &ambiguous, 1)]);
    BinaryWriter::u32_le(120, &mut bytes[32 + 5 + "ambiguous.txt".len() + 2..]);
    let path = file(&bytes);
    let archive = YpfArchive::open(
        Arc::new(ArcView::open(&path.0)?),
        None,
        None,
        Compression::ExternalSnappy,
    )?;
    assert_eq!(
        &*archive.open_entry(&archive.entries()[0])?,
        &vec![b'a'; 120]
    );
    Ok(())
}
fn fixture(records: &[(&str, &[u8], u8)]) -> Vec<u8> {
    fixture_version(0x1ee, records)
}
fn fixture_version(version: u32, records: &[(&str, &[u8], u8)]) -> Vec<u8> {
    fixture_scheme(version, records, ChecksumScheme::Crc32Adler32)
}
fn fixture_scheme(version: u32, records: &[(&str, &[u8], u8)], scheme: ChecksumScheme) -> Vec<u8> {
    let width = if version < 0x1df { 4 } else { 8 };
    let record_size = 19 + width;
    let index_end = 32
        + records
            .iter()
            .map(|(name, _, _)| record_size + name.len())
            .sum::<usize>();
    let mut bytes = vec![0; 32];
    bytes[..4].copy_from_slice(b"YPF\0");
    for (offset, value) in [
        (4, version),
        (8, records.len() as u32),
        (12, index_end as u32),
    ] {
        BinaryWriter::u32_le(value, &mut bytes[offset..]);
    }
    let mut offset = index_end as u64;
    for (name, data, packed) in records {
        let mut record = vec![0; record_size + name.len()];
        let hash = match scheme {
            ChecksumScheme::Murmur2 => vnlens_crypto::hash::murmur2::hash(name.as_bytes(), 0),
            ChecksumScheme::Crc32Adler32 => crc32::ieee(0, name.as_bytes()),
        };
        BinaryWriter::u32_le(hash, &mut record);
        let mut length = name.len() as u8;
        let swaps = if version < 0x198 {
            LENGTH_SWAPS_EARLY
        } else if version == 0x1f4 {
            LENGTH_SWAPS_1F4
        } else {
            LENGTH_SWAPS_PRE_1F4
        };
        for &(a, b) in swaps {
            if length == a {
                length = b;
                break;
            }
            if length == b {
                length = a;
                break;
            }
        }
        record[4] = !length;
        for (out, &byte) in record[5..5 + name.len()].iter_mut().zip(name.as_bytes()) {
            *out = byte ^ 0xa7;
        }
        let at = 5 + name.len();
        record[at] = 0;
        record[at + 1] = *packed;
        BinaryWriter::u32_le(data.len() as u32, &mut record[at + 2..]);
        BinaryWriter::u32_le(data.len() as u32, &mut record[at + 6..]);
        if width == 4 {
            BinaryWriter::u32_le(offset as u32, &mut record[at + 10..]);
        } else {
            BinaryWriter::u64_le(offset, &mut record[at + 10..]);
        }
        let checksum = match scheme {
            ChecksumScheme::Murmur2 => vnlens_crypto::hash::murmur2::hash(data, 0),
            ChecksumScheme::Crc32Adler32 => adler32::checksum(data),
        };
        BinaryWriter::u32_le(checksum, &mut record[at + 10 + width..]);
        offset += data.len();
        bytes.extend(record);
    }
    for (_, data, _) in records {
        bytes.extend_from_slice(data);
    }
    bytes
}

fn single_entry_fixture(width: usize, key: u8, checksum_scheme: ChecksumScheme) -> Vec<u8> {
    // 50-byte name uses the historic 46<->50 substitution even in 0x1F4.
    let name = format!("{}.bin", "r".repeat(46));
    let end = 32 + 19 + width + name.len();
    let mut bytes = vec![0; end];
    bytes[..4].copy_from_slice(b"YPF\0");
    for (at, word) in [
        (4, 0x1f4),
        (8, 1),
        (12, end as u32),
        (32, checksum_scheme.filename(name.as_bytes())),
    ] {
        BinaryWriter::u32_le(word, &mut bytes[at..]);
    }
    bytes[36] = !46;
    for (out, byte) in bytes[37..37 + name.len()].iter_mut().zip(name.bytes()) {
        *out = byte ^ key;
    }
    let at = 37 + name.len();
    BinaryWriter::u32_le(3, &mut bytes[at + 2..]);
    BinaryWriter::u32_le(3, &mut bytes[at + 6..]);
    if width == 4 {
        BinaryWriter::u32_le(end as u32, &mut bytes[at + 10..]);
    } else {
        BinaryWriter::u64_le(end as u64, &mut bytes[at + 10..]);
    }
    let checksum = match checksum_scheme {
        ChecksumScheme::Murmur2 => 0x1357_7c9b,
        ChecksumScheme::Crc32Adler32 => 0x024d_0127,
    };
    BinaryWriter::u32_le(checksum, &mut bytes[at + 10 + width..]);
    bytes.extend_from_slice(b"abc");
    bytes
}

#[test]
fn checksum_vectors_and_mixed_index_schemes() {
    assert_eq!(ChecksumScheme::Murmur2.filename(b"hello"), 0xe561_29cb);
    assert_eq!(ChecksumScheme::Crc32Adler32.filename(b"hello"), 0x3610_a686);
    assert_eq!(ChecksumScheme::Murmur2.payload(b"abc"), 0x1357_7c9b);
    assert_eq!(ChecksumScheme::Crc32Adler32.payload(b"abc"), 0x024d_0127);
    let first = single_entry_fixture(8, 0x37, ChecksumScheme::Murmur2);
    let second = single_entry_fixture(8, 0x37, ChecksumScheme::Crc32Adler32);
    let old_end = BinaryReader::u32_le(&first[12..]) as usize;
    let end = 32 + (old_end - 32) * 2;
    let mut bytes = first[..32].to_vec();
    bytes.extend_from_slice(&first[32..old_end]);
    bytes.extend_from_slice(&second[32..old_end]);
    BinaryWriter::u32_le(2, &mut bytes[8..]);
    BinaryWriter::u32_le(end as u32, &mut bytes[12..]);
    for record in [32, old_end] {
        BinaryWriter::u64_le(end as u64, &mut bytes[record + 5 + 50 + 10..]);
    }
    bytes.extend_from_slice(b"abc");
    let source: Arc<[u8]> = bytes.into();
    assert!(read_index(&source, Some(0x37), None).is_err());
    assert!(read_index(&source, None, None).is_err());
}

#[test]
fn earlier_versions_use_32_bit_offsets_and_crc32_adler32() {
    for version in [0xea, 0x12c, 0x198, 0x1c6, 0x1d0, 0x1da, 0x1dc, 0x1de] {
        let mut bytes = single_entry_fixture(4, 0x37, ChecksumScheme::Crc32Adler32);
        BinaryWriter::u32_le(version, &mut bytes[4..]);
        let source: Arc<[u8]> = bytes.clone().into();
        let index = read_index(&source, None, None).unwrap();
        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.entries[0].name, format!("{}.bin", "r".repeat(46)));
        assert_eq!(index.checksum_scheme, ChecksumScheme::Crc32Adler32);
        assert_eq!(
            &*read_entry(
                &source,
                &index.entries[0],
                index.checksums[0],
                index.checksum_scheme,
                Compression::Zlib
            )
            .unwrap(),
            b"abc"
        );
        bytes[32] ^= 1;
        let corrupt: Arc<[u8]> = bytes.into();
        assert!(read_index(&corrupt, Some(0x37), None).is_err());
        let mut wider = single_entry_fixture(8, 0x37, ChecksumScheme::Crc32Adler32);
        BinaryWriter::u32_le(version, &mut wider[4..]);
        let wider: Arc<[u8]> = wider.into();
        assert!(read_index(&wider, None, None).is_err());
    }
    for version in [0xe9, 0x1f5] {
        let mut bytes = single_entry_fixture(4, 0x37, ChecksumScheme::Crc32Adler32);
        BinaryWriter::u32_le(version, &mut bytes[4..]);
        let source: Arc<[u8]> = bytes.into();
        assert!(matches!(
            read_index(&source, None, None),
            Err(Error::Unsupported(_))
        ));
    }
}

#[test]
fn earlier_length_variants_require_complete_index_validation() {
    let names = [3, 6, 12, 17, 28].map(|length| "x".repeat(length));
    let records: Vec<_> = names
        .iter()
        .map(|name| (name.as_str(), &b"abc"[..], 0))
        .collect();
    for version in [0x12c, 0x198] {
        let mut bytes = fixture_version(version, &records);
        BinaryWriter::u32_le(0x12c, &mut bytes[4..]);
        let source: Arc<[u8]> = bytes.into();
        let index = read_index(&source, None, None).unwrap();
        assert_eq!(
            index
                .entries
                .iter()
                .map(|entry| &entry.name)
                .collect::<Vec<_>>(),
            names.iter().collect::<Vec<_>>()
        );
    }
    let mut bytes = fixture_version(0x12c, &records);
    BinaryWriter::u32_le(0x198, &mut bytes[4..]);
    let source: Arc<[u8]> = bytes.into();
    assert!(read_index(&source, None, None).is_err());
}

#[test]
fn index_recovery_is_lazy_and_payload_corruption_stays_local() {
    struct IndexOnly {
        bytes: Arc<[u8]>,
        end: u64,
    }
    impl ReadAt for IndexOnly {
        fn len(&self) -> u64 {
            self.bytes.len()
        }
        fn read_at(&self, offset: u64, size: usize) -> std::io::Result<Cow<'_, [u8]>> {
            assert!(
                offset + size as u64 <= self.end,
                "Index recovery read payload bytes"
            );
            self.bytes.read_at(offset, size)
        }
    }
    let mut bytes = single_entry_fixture(4, 0x37, ChecksumScheme::Crc32Adler32);
    let end = u64::from(BinaryReader::u32_le(&bytes[12..]));
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let source = IndexOnly {
        bytes: bytes.clone().into(),
        end,
    };
    let index = read_index(&source, None, None).unwrap();
    assert_eq!(index.name_key.unwrap().bytes(), [0x37]);
    assert!(read_index(&source, Some(0x36), None).is_err());
    let bytes: Arc<[u8]> = bytes.into();
    assert!(
        read_entry(
            &bytes,
            &index.entries[0],
            index.checksums[0],
            index.checksum_scheme,
            Compression::Zlib
        )
        .is_err()
    );
    assert!(matches!(
        read_index(&source, None, Some(&AtomicBool::new(true))),
        Err(Error::Cancelled)
    ));
    for end in 0..source.end as usize {
        let bytes: Arc<[u8]> = source.bytes[..end].into();
        assert!(read_index(&bytes, None, None).is_err());
    }
}

#[test]
fn pe_script_keys_take_precedence_and_missing_keys_are_recovered_lazily() {
    let mut script = vec![0; 32];
    script[..4].copy_from_slice(b"YSTB");
    for (at, value) in [(4, 0x227), (8, 2), (12, 8), (16, 24), (20, 12), (24, 8)] {
        BinaryWriter::u32_le(value, &mut script[at..]);
    }
    script.extend_from_slice(&[0, 1, 0, 0, 0, 1, 0, 0]);
    for offset in [4, 0] {
        let mut arg = [0; 12];
        BinaryWriter::u32_le(4, &mut arg[4..]);
        BinaryWriter::u32_le(offset, &mut arg[8..]);
        script.extend_from_slice(&arg);
    }
    script.extend_from_slice(b"abcdefghijkl");
    script.extend_from_slice(&[0; 8]);
    let plain_script = script.clone();
    vnlens_script::yuris::decrypt_ystb(&mut script, &[0x12, 0x34, 0x56, 0x78]).unwrap();

    let mut commands = vec![0; 16];
    commands[..4].copy_from_slice(b"YSCM");
    BinaryWriter::u32_le(0x227, &mut commands[4..]);
    BinaryWriter::u32_le(1, &mut commands[8..]);
    commands.extend_from_slice(b"WORD\0\0");

    let mut bytes = fixture_version(
        0x1f4,
        &[
            ("ysbin/ysc.ybn", &commands, 0),
            ("ysbin/yst00001.ybn", &script, 0),
            ("broken.bin", b"bad", 0),
        ],
    );
    // Corrupt the unrelated third entry's payload checksum; mounting and reading
    // the script entry with recovered keys must not touch broken.bin.
    let third = 32 + (27 + "ysbin/ysc.ybn".len()) + (27 + "ysbin/yst00001.ybn".len());
    bytes[third + 5 + "broken.bin".len() + 18] ^= 1;
    let file = file(&bytes);
    for hint in [None, Some([0x12, 0x34, 0x56, 0x78])] {
        let archive = YpfArchive::open(
            Arc::new(ArcView::open(&file.0).unwrap()),
            hint,
            None,
            Compression::Zlib,
        )
        .unwrap();
        assert_eq!(archive.entries().len(), 3);
        assert!(archive.script_key.get().is_none());
        assert!(
            archive
                .open_entry_source(&archive.entries()[1])
                .unwrap()
                .is_none()
        );
        let decrypted = archive.open_entry(&archive.entries()[1]).unwrap();
        assert_eq!(&*decrypted, plain_script);
        assert_eq!(archive.script_key.get(), Some(&[0x12, 0x34, 0x56, 0x78]));
        assert!(archive.open_entry(&archive.entries()[2]).is_err());
    }
    let pe_key = [0xff; 4];
    let archive = YpfArchive::open(
        Arc::new(ArcView::open(&file.0).unwrap()),
        Some(pe_key),
        None,
        Compression::Zlib,
    )
    .unwrap();
    let mut expected = script.clone();
    vnlens_script::yuris::decrypt_ystb(&mut expected, &pe_key).unwrap();
    assert_eq!(
        &*archive.open_entry(&archive.entries()[1]).unwrap(),
        expected
    );
    assert_ne!(expected, plain_script);
    assert_eq!(archive.script_key.get(), Some(&pe_key));
    // PE-key access must not open even the command-table payload.
    let mut bad_commands = bytes;
    bad_commands[32 + 5 + "ysbin/ysc.ybn".len() + 18] ^= 1;
    let bad_path = self::file(&bad_commands);
    let archive = YpfArchive::open(
        Arc::new(ArcView::open(&bad_path.0).unwrap()),
        Some([0x12, 0x34, 0x56, 0x78]),
        None,
        Compression::Zlib,
    )
    .unwrap();
    assert_eq!(
        &*archive.open_entry(&archive.entries()[1]).unwrap(),
        plain_script
    );
    assert!(archive.open_entry(&archive.entries()[0]).is_err());
    let patch = self::file(&fixture_version(
        0x1f4,
        &[("ysbin/yst00001.ybn", &script, 0)],
    ));
    let archive = YpfArchive::open(
        Arc::new(ArcView::open(&patch.0).unwrap()),
        Some([0x12, 0x34, 0x56, 0x78]),
        None,
        Compression::Zlib,
    )
    .unwrap();
    assert!(archive.script_key.get().is_none());
    assert_eq!(
        &*archive.open_entry(&archive.entries()[0]).unwrap(),
        plain_script
    );
}

#[test]
fn ambiguous_scripts_use_unique_archive_evidence_and_validate_the_original_candidate() {
    let script = |size: usize, offsets: [u32; 2]| {
        let mut bytes = vec![0; 32];
        bytes[..4].copy_from_slice(b"YSTB");
        for (offset, value) in [
            (4, 0x227),
            (8, 2),
            (12, 8),
            (16, 24),
            (20, size as u32),
            (24, 8),
        ] {
            BinaryWriter::u32_le(value, &mut bytes[offset..]);
        }
        bytes.extend_from_slice(&[0, 1, 0, 0, 0, 1, 0, 0]);
        for offset in offsets {
            let mut argument = [0; 12];
            BinaryWriter::u32_le(4, &mut argument[4..]);
            BinaryWriter::u32_le(offset, &mut argument[8..]);
            bytes.extend_from_slice(&argument);
        }
        bytes.resize(bytes.len() + size + 8, 0);
        bytes
    };
    let small = script(8, [0, 4]);
    let ambiguous = script(48, [0, 4]);
    let unique = script(32, [0, 0]);
    let mut commands = vec![0; 16];
    commands[..4].copy_from_slice(b"YSCM");
    BinaryWriter::u32_le(0x227, &mut commands[4..]);
    BinaryWriter::u32_le(5, &mut commands[8..]);
    for _ in 0..5 {
        commands.extend_from_slice(b"WORD\0\0");
    }
    let definitions = vnlens_script::yuris::commands(&commands, None).unwrap().0;
    assert!(matches!(
        vnlens_script::yuris::recover_ystb_key(&small, &definitions, &AtomicBool::new(false)),
        Err(Error::UnknownScheme(_))
    ));
    let data = fixture_version(
        0x1f4,
        &[
            ("ysbin/ysc.ybn", &commands, 0),
            ("ysbin/yst00000.ybn", &small, 0),
            ("ysbin/yst00002.ybn", &ambiguous, 0),
            ("ysbin/yst00001.ybn", &unique, 0),
        ],
    );
    let path = file(&data);
    let archive = YpfArchive::open(
        Arc::new(ArcView::open(&path.0).unwrap()),
        None,
        None,
        Compression::Zlib,
    )
    .unwrap();
    assert!(archive.script_key.get().is_none());
    assert_eq!(&*archive.open_entry(&archive.entries()[1]).unwrap(), small);
    assert_eq!(archive.script_key.get(), Some(&[0; 4]));
    assert_eq!(
        &*archive.open_entry(&archive.entries()[2]).unwrap(),
        ambiguous
    );
    let path = file(&fixture_version(
        0x1f4,
        &[
            ("ysbin/ysc.ybn", &commands, 0),
            ("ysbin/yst00000.ybn", &small, 0),
        ],
    ));
    let unresolved = YpfArchive::open(
        Arc::new(ArcView::open(&path.0).unwrap()),
        None,
        None,
        Compression::Zlib,
    )
    .unwrap();
    assert!(matches!(
        unresolved.open_entry(&unresolved.entries()[1]),
        Err(Error::UnknownScheme(_))
    ));
    assert!(unresolved.script_key.get().is_none());
    let mut conflicting = unique;
    vnlens_script::yuris::decrypt_ystb(&mut conflicting, &[8, 0, 0, 0]).unwrap();
    let path = file(&fixture_version(
        0x1f4,
        &[
            ("ysbin/ysc.ybn", &commands, 0),
            ("ysbin/yst00000.ybn", &small, 0),
            ("ysbin/yst00001.ybn", &conflicting, 0),
        ],
    ));
    let conflict = YpfArchive::open(
        Arc::new(ArcView::open(&path.0).unwrap()),
        None,
        None,
        Compression::Zlib,
    )
    .unwrap();
    assert!(matches!(
        conflict.open_entry(&conflict.entries()[1]),
        Err(Error::UnknownScheme(_))
    ));
    assert!(conflict.script_key.get().is_none());
}

#[test]
fn same_version_checksum_variants_are_kept_for_direct_and_streamed_reads() {
    use std::io::{Read, Write};
    let plain = b"stored bytes and compressed bytes must use the index-selected checksum";
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(plain).unwrap();
    let compressed = encoder.finish().unwrap();
    for scheme in [ChecksumScheme::Murmur2, ChecksumScheme::Crc32Adler32] {
        for version in [0x1df, 0x1ee, 0x1f4] {
            let mut bytes = fixture_scheme(
                version,
                &[("stored.bin", plain, 0), ("packed.bin", &compressed, 1)],
                scheme,
            );
            let second = 32 + 27 + "stored.bin".len();
            BinaryWriter::u32_le(
                plain.len() as u32,
                &mut bytes[second + 5 + "packed.bin".len() + 2..],
            );
            let path = file(&bytes);
            let archive = YpfArchive::open(
                Arc::new(ArcView::open(&path.0).unwrap()),
                Some([0; 4]),
                Some(0xa7),
                Compression::Zlib,
            )
            .unwrap();
            assert_eq!(archive.checksum_scheme, scheme);
            for entry in archive.entries() {
                assert_eq!(&*archive.open_entry(entry).unwrap(), plain);
                let source = archive.open_entry_source(entry).unwrap().unwrap();
                assert_eq!(&*source.read_at(1, 7).unwrap(), &plain[1..8]);
                let mut reader = source
                    .reader(Arc::new(std::sync::atomic::AtomicBool::new(false)))
                    .unwrap();
                let mut decoded = Vec::new();
                reader.read_to_end(&mut decoded).unwrap();
                assert_eq!(decoded, plain);
            }
            // A payload checksum from the other scheme must remain corruption.
            let wrong = match scheme {
                ChecksumScheme::Murmur2 => adler32::checksum(plain),
                ChecksumScheme::Crc32Adler32 => vnlens_crypto::hash::murmur2::hash(plain, 0),
            };
            BinaryWriter::u32_le(wrong, &mut bytes[32 + 5 + "stored.bin".len() + 18..]);
            drop(archive);
            fs::write(&path.0, &bytes).unwrap();
            let archive = YpfArchive::open(
                Arc::new(ArcView::open(&path.0).unwrap()),
                Some([0; 4]),
                Some(0xa7),
                Compression::Zlib,
            )
            .unwrap();
            assert!(archive.open_entry(&archive.entries()[0]).is_err());
            let source = archive
                .open_entry_source(&archive.entries()[0])
                .unwrap()
                .unwrap();
            assert!(source.read_at(0, plain.len()).is_err());
            assert_eq!(&*archive.open_entry(&archive.entries()[1]).unwrap(), plain);
        }
    }
}

#[test]
fn version_1f4_lengths_compression_and_lazy_checksum_validation() {
    use std::io::{Read, Write};
    let plain = b"a compressed entry with repeated repeated repeated words";
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(plain).unwrap();
    let compressed = encoder.finish().unwrap();
    // These lengths exercise every pair that differs from the 0x1EE table.
    for (length, encoded) in [
        (3, 0xf5),
        (10, 0xfc),
        (17, 0xe7),
        (24, 0xee),
        (20, 0xd1),
        (46, 0xeb),
        (25, 0xe6),
    ] {
        let name = "n".repeat(length);
        let mut bytes = fixture_version(0x1f4, &[("broken", b"bad", 0), (&name, &compressed, 1)]);
        let second = 32 + 27 + "broken".len();
        assert_eq!(bytes[second + 4], encoded);
        BinaryWriter::u32_le(plain.len() as u32, &mut bytes[second + 5 + length + 2..]);
        // A bad payload checksum must not affect mounting or another entry.
        bytes[32 + 5 + "broken".len() + 18] ^= 1;
        let file = file(&bytes);
        let archive = YpfArchive::open(
            Arc::new(ArcView::open(&file.0).unwrap()),
            Some([0; 4]),
            Some(0xa7),
            Compression::Zlib,
        )
        .unwrap();
        let entry = &archive.entries()[1];
        assert_eq!(entry.name, name);
        assert_eq!(&*archive.open_entry(entry).unwrap(), plain);
        assert_eq!(&*archive.open_entry_raw(entry).unwrap(), compressed);
        let source = archive.open_entry_source(entry).unwrap().unwrap();
        let mut reader = source
            .reader(Arc::new(std::sync::atomic::AtomicBool::new(false)))
            .unwrap();
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, plain);
        assert!(archive.open_entry(&archive.entries()[0]).is_err());
        assert!(
            YpfArchive::open(
                Arc::new(ArcView::open(&file.0).unwrap()),
                Some([0; 4]),
                Some(0xff),
                Compression::Zlib
            )
            .is_err()
        );
    }
}

#[test]
fn rejects_truncated_index_and_out_of_range_64_bit_offsets() {
    let mut bytes = fixture(RECORDS);
    let first_offset = 32 + 5 + "bad.ybn".len() + 10;
    BinaryWriter::u64_le(0x1_0000_0000, &mut bytes[first_offset..]);
    let file = file(&bytes);
    assert!(
        YpfArchive::open(
            Arc::new(ArcView::open(&file.0).unwrap()),
            Some([0; 4]),
            Some(0xa7),
            Compression::Zlib
        )
        .is_err()
    );
    fs::write(&file.0, &bytes[..40]).unwrap();
    assert!(
        YpfArchive::open(
            Arc::new(ArcView::open(&file.0).unwrap()),
            Some([0; 4]),
            Some(0xa7),
            Compression::Zlib
        )
        .is_err()
    );
}

#[test]
fn virtual_paths_read_only_the_script_list_and_preserve_entry_names() {
    let path = b"story\\main.yst";
    let mut table = vec![0; 20];
    table[..4].copy_from_slice(b"YSTL");
    BinaryWriter::u32_le(0x1ee, &mut table[4..]);
    BinaryWriter::u32_le(1, &mut table[8..]);
    BinaryWriter::u32_le(3, &mut table[12..]);
    BinaryWriter::u32_le(path.len() as u32, &mut table[16..]);
    table.extend_from_slice(path);
    table.resize(table.len() + 20, 0);
    let mut bytes = fixture(&[
        ("ysbin/yst00003.ybn", b"x", 1),
        ("ysbin/yst00004.ybn", b"other", 0),
        ("ysbin/yst_list.ybn", &table, 0),
    ]);
    let file = file(&bytes);
    let archive = YpfArchive::open(
        Arc::new(ArcView::open(&file.0).unwrap()),
        Some([0; 4]),
        Some(0xa7),
        Compression::Zlib,
    )
    .unwrap();
    assert_eq!(archive.entries()[0].name, "ysbin/yst00003.ybn");
    assert_eq!(
        archive.virtual_paths().unwrap(),
        [(0, "story\\main.yst".into())]
    );
    assert!(archive.open_entry(&archive.entries()[0]).is_err());
    drop(archive);
    let table_offset = bytes.len() - table.len();
    bytes[table_offset] = b'X';
    fs::write(&file.0, bytes).unwrap();
    let archive = YpfArchive::open(
        Arc::new(ArcView::open(&file.0).unwrap()),
        Some([0; 4]),
        Some(0xa7),
        Compression::Zlib,
    )
    .unwrap();
    assert_eq!(archive.entries().len(), 3);
    assert!(archive.virtual_paths().is_err());
}
