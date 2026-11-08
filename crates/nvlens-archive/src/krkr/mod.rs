//! KiriKiri XP3. XP3Archive.cpp uses LE chunk lengths and segment
//! descriptors; Hxv4 adds an out-of-line tag-prefix XChaCha20-Poly1305 table.
//! Mounting reads only the standard and optional Hxv4 indices. Entry segments are inflated then filtered
//! at their logical offsets and checked against the plaintext Adler-32.
mod names;
mod read;
mod special;
pub use names::{NameProgress, NameRecovery};
use nvlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, Packed, ResourceKind, Result,
};
use nvlens_crypto::{
    checksum::adler32,
    cipher::hxv4::{self, Filter},
    compress::zlib,
};
use nvlens_io::{ArcView, BinaryReader};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
const SIGNATURES: &[u32] = &[0x0d33_5058];
const MAGIC: &[u8; 11] = b"XP3\r\n \n\x1a\x8bg\x01";
#[derive(Debug, Default)]
struct Xp3;
impl Format for Xp3 {
    fn tag(&self) -> &'static str {
        "xp3/krkr"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["xp3"]
    }
    fn description(&self) -> &'static str {
        "KiriKiri XP3 archive"
    }
}
fn corrupt(offset: u64, reason: impl Into<String>) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}
fn key<'a>(options: &'a ArchiveOptions, name: &str) -> Result<&'a [u8]> {
    options
        .keys
        .get(name)
        .map(|v| v.bytes())
        .ok_or_else(|| Error::UnknownScheme(Some(format!("Missing {name}"))))
}
fn fixed<const N: usize>(bytes: &[u8]) -> Result<&[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| Error::UnknownScheme(Some("Invalid Hxv4 key length".into())))
}
fn inflate(bytes: &[u8], size: u64, offset: u64) -> Result<Vec<u8>> {
    let size =
        usize::try_from(size).map_err(|_| corrupt(offset, "XP3 size does not fit memory"))?;
    let out = zlib::inflate_with_limit(bytes, size)
        .map_err(|e| corrupt(offset, format!("XP3 zlib: {e}")))?;
    if out.len() != size {
        return Err(corrupt(offset, "XP3 decoded length mismatch"));
    }
    Ok(out)
}
fn chunk<'a>(r: &mut BinaryReader<'a>) -> Result<(&'a [u8], &'a [u8])> {
    let tag = r.read_bytes(4)?;
    let len = r.read_u64_le()?;
    let len = usize::try_from(len)
        .map_err(|_| corrupt(r.position() as u64, "XP3 chunk size does not fit memory"))?;
    Ok((tag, r.read_bytes(len)?))
}
#[derive(Debug)]
struct Segment {
    offset: u64,
    stored: u64,
    size: u64,
    compressed: bool,
}
struct Record {
    name: String,
    flags: u32,
    size: u64,
    stored: u64,
    segments: Vec<Segment>,
    adler: Option<u32>,
    filter: Option<(u64, u16)>,
}
struct Xp3Archive {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
    records: Vec<Record>,
    names: BTreeMap<String, usize>,
    filter: Option<Filter>,
    xor31: bool,
}
impl ArchiveFormat for Xp3 {
    fn open(&self, view: &Arc<ArcView>, options: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        Ok(Box::new(Xp3Archive::open(view, options)?))
    }
}
impl Xp3Archive {
    fn open(view: &Arc<ArcView>, options: &ArchiveOptions) -> Result<Self> {
        let mut header = BinaryReader::new(view.slice(0, 19)?);
        if header.read_bytes(11)? != MAGIC {
            return Err(Error::InvalidFormat);
        }
        let mut position = header.read_u64_le()?;
        let use_hxv4 = match options.numbers.get("hxv4").copied().unwrap_or(0) {
            0 => false,
            1 => true,
            _ => return Err(Error::Unsupported("XP3 Hxv4 option".into())),
        };
        let xor31 = match options.numbers.get("xp3_xor31").copied().unwrap_or(0) {
            0 => false,
            1 if !use_hxv4 => true,
            _ => {
                return Err(Error::Unsupported(
                    "Conflicting or invalid XP3 filter options".into(),
                ));
            }
        };
        let filter = if use_hxv4 {
            let nonce = fixed::<24>(key(options, "hxv4_nonce0")?)?;
            let table = fixed::<4096>(key(options, "hxv4_table")?)?;
            let words = table
                .as_chunks::<4>()
                .0
                .iter()
                .map(|b| BinaryReader::u32_le(b))
                .collect::<Vec<_>>();
            Some(
                Filter::from_params_and_table(key(options, "hxv4_params")?, &words)
                    .map_err(|e| Error::UnknownScheme(Some(e)))?
                    .with_holder_words(
                        BinaryReader::u32_le(nonce),
                        BinaryReader::u32_le(&nonce[4..]),
                    ),
            )
        } else {
            None
        };
        let mut visited = BTreeSet::new();
        let mut records = Vec::new();
        let mut bindings = None;
        loop {
            if !visited.insert(position) {
                return Err(corrupt(position, "Cyclic XP3 index chain"));
            }
            let flag = view.slice(position, 1)?[0];
            let mut h =
                BinaryReader::new(view.slice(position + 1, if flag & 7 == 1 { 16 } else { 8 })?);
            let stored = h.read_u64_le()?;
            let size = if flag & 7 == 1 {
                h.read_u64_le()?
            } else {
                stored
            };
            let start = position + 1 + h.position() as u64;
            let stored_bytes = view.slice(start, stored)?;
            let decoded = match flag & 7 {
                0 => Cow::Borrowed(stored_bytes),
                1 => Cow::Owned(inflate(stored_bytes, size, start)?),
                _ => return Err(Error::Unsupported("XP3 index encoding".into())),
            };
            let mut r = BinaryReader::new(&decoded);
            while r.remaining() != 0 {
                let (tag, bytes) = chunk(&mut r)?;
                match tag {
                    b"Hxv4" => {
                        if !use_hxv4 {
                            return Err(Error::UnknownScheme(Some(
                                "Hxv4 was not enabled by engine identification".into(),
                            )));
                        }
                        let index_key = fixed::<32>(key(options, "hxv4_index")?)?;
                        let nonce0 = fixed::<24>(key(options, "hxv4_nonce0")?)?;
                        let nonce1 = fixed::<24>(key(options, "hxv4_nonce1")?)?;
                        let mut d = BinaryReader::new(bytes);
                        let offset = d.read_u64_le()?;
                        let len = u64::from(d.read_u32_le()?);
                        let flags = d.read_u16_le()?;
                        if d.remaining() != 0 || bindings.is_some() {
                            return Err(corrupt(position, "Invalid or duplicate Hxv4 descriptor"));
                        }
                        let plain = hxv4::authenticate(
                            view.slice(offset, len)?,
                            index_key,
                            if flags & 1 == 0 { nonce0 } else { nonce1 },
                        )
                        .map_err(|e| corrupt(offset, e))?;
                        let mut p = BinaryReader::new(&plain);
                        let size = u64::from(p.read_u32_le()?);
                        let table = inflate(p.read_bytes(p.remaining())?, size, offset)?;
                        bindings = Some(special::read(&table)?);
                    }
                    b"File" => records.push(parse_file(bytes, view.len())?),
                    _ => {}
                }
            }
            if flag & 0x80 == 0 {
                break;
            }
            position = BinaryReader::u64_le(view.slice(start + stored, 8)?);
        }
        let has_hxv4 = bindings.is_some();
        let mut bindings = bindings.unwrap_or_default();
        let mut entries = Vec::new();
        let mut names = BTreeMap::new();
        let mut selected = Vec::new();
        for mut record in records {
            // Slot zero addresses this physical XP3; other slots refer to
            // companion archives and cannot rename this archive's payloads.
            let aliases = bindings
                .remove(&(0, record.name.clone()))
                .unwrap_or_default();
            record.filter = aliases.first().map(|binding| binding.filter);
            // The protected warning node uses reserved id zero, no protection
            // flag and a raw segment whose size differs from its fictitious
            // info sizes. Recognize this index shape without reading its payload.
            if has_hxv4
                && record.name == "\u{5000}"
                && record.flags == 0
                && matches!(record.segments.as_slice(), [s] if !s.compressed && s.size != record.size)
            {
                continue;
            }
            // The explicit startup.tjs boot stub is read before the filter is
            // installed. Its XP3 protection flag is set, but its bytes are plain;
            // the authenticated id-zero record names the virtual startup instead.
            if record.flags & 0x8000_0000 != 0
                && record.filter.is_none()
                && !xor31
                && !(has_hxv4 && record.name.eq_ignore_ascii_case("startup.tjs"))
            {
                return Err(Error::UnknownScheme(Some(
                    "XP3 entry encryption was not resolved by the selected engine".into(),
                )));
            }
            if xor31 && record.flags & 0x8000_0000 != 0 && record.adler.is_none() {
                return Err(corrupt(position, "XP3 hash filter requires an adlr record"));
            }
            let mut size = 0u64;
            let mut stored = 0u64;
            let mut begin = u64::MAX;
            let mut end = 0u64;
            for s in &record.segments {
                size = size
                    .checked_add(s.size)
                    .ok_or_else(|| corrupt(s.offset, "XP3 logical size overflow"))?;
                stored = stored
                    .checked_add(s.stored)
                    .ok_or_else(|| corrupt(s.offset, "XP3 stored size overflow"))?;
                begin = begin.min(s.offset);
                end = end.max(s.offset + s.stored);
            }
            if size != record.size || stored != record.stored {
                return Err(corrupt(
                    begin,
                    format!(
                        "XP3 info/segment size mismatch for {:?}: info {}/{}, segments {}/{}, protected {}",
                        record.name,
                        record.size,
                        record.stored,
                        size,
                        stored,
                        record.filter.is_some()
                    ),
                ));
            }
            if record.segments.is_empty() {
                begin = 0;
            }
            let paths = if aliases.is_empty() {
                vec![record.name.clone()]
            } else {
                aliases.into_iter().map(|binding| binding.path).collect()
            };
            let packed = Packed {
                unpacked_size: size,
                is_packed: record.segments.iter().any(|s| s.compressed),
            };
            for path in paths {
                let entry = Entry {
                    kind: ResourceKind::guess_from_name(&path),
                    name: path,
                    offset: begin,
                    size: end - begin,
                    packed: Some(packed),
                };
                if names.insert(entry.name.clone(), selected.len()).is_some() {
                    return Err(corrupt(begin, "Duplicate XP3 entry path"));
                }
                entries.push(entry);
            }
            selected.push(record);
        }
        Ok(Xp3Archive {
            view: view.clone(),
            entries,
            records: selected,
            names,
            filter,
            xor31,
        })
    }
}
fn parse_file(bytes: &[u8], file_len: u64) -> Result<Record> {
    let mut r = BinaryReader::new(bytes);
    let mut info = None;
    let mut segments = None;
    let mut adler = None;
    while r.remaining() != 0 {
        let (tag, data) = chunk(&mut r)?;
        let mut c = BinaryReader::new(data);
        match tag {
            b"info" => {
                if info.is_some() {
                    return Err(corrupt(0, "Duplicate XP3 info"));
                }
                let flags = c.read_u32_le()?;
                let size = c.read_u64_le()?;
                let stored = c.read_u64_le()?;
                let n = c.read_u16_le()?;
                let mut name = Vec::new();
                for _ in 0..n {
                    name.push(c.read_u16_le()?);
                }
                let name =
                    String::from_utf16(&name).map_err(|_| corrupt(0, "Invalid XP3 UTF-16 name"))?;
                info = Some((name, flags, size, stored));
            }
            b"segm" => {
                if segments.is_some() {
                    return Err(corrupt(0, "Duplicate XP3 segments"));
                }
                let mut list = Vec::new();
                while c.remaining() != 0 {
                    let flags = c.read_u32_le()?;
                    let offset = c.read_u64_le()?;
                    let size = c.read_u64_le()?;
                    let stored = c.read_u64_le()?;
                    if flags & !1 != 0 {
                        return Err(Error::Unsupported("XP3 segment flags".into()));
                    }
                    if offset > file_len || stored > file_len - offset {
                        return Err(nvlens_io::BinaryIo::unexpected_eof(
                            "XP3 segment exceeds archive",
                        )
                        .into());
                    }
                    if flags == 0 && size != stored {
                        return Err(corrupt(offset, "Uncompressed XP3 segment length mismatch"));
                    }
                    list.push(Segment {
                        offset,
                        stored,
                        size,
                        compressed: flags != 0,
                    });
                }
                segments = Some(list);
            }
            b"adlr" => {
                if adler.is_some() || data.len() != 4 {
                    return Err(corrupt(0, "Invalid XP3 checksum record"));
                }
                adler = Some(c.read_u32_le()?);
            }
            _ => {}
        }
    }
    let (name, flags, size, stored) = info.ok_or_else(|| corrupt(0, "Missing XP3 info"))?;
    let segments = segments.ok_or_else(|| corrupt(0, "Missing XP3 segments"))?;
    Ok(Record {
        name,
        flags,
        size,
        stored,
        segments,
        adler,
        filter: None,
    })
}
impl Xp3Archive {
    fn record(&self, entry: &Entry) -> Result<&Record> {
        self.names
            .get(&entry.name)
            .map(|&i| &self.records[i])
            .ok_or_else(|| corrupt(entry.offset, "Entry does not belong to this XP3"))
    }
}
impl Archive for Xp3Archive {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let record = self.record(entry)?;
        if record.filter.is_none()
            && !(self.xor31 && record.flags & 0x8000_0000 != 0)
            && let [s] = record.segments.as_slice()
            && !s.compressed
        {
            let bytes = self.view.slice(s.offset, s.stored)?;
            if record
                .adler
                .is_some_and(|sum| adler32::checksum(bytes) != sum)
            {
                return Err(corrupt(s.offset, "XP3 plaintext checksum mismatch"));
            }
            return Ok(Cow::Borrowed(bytes));
        }
        self.read_cancellable(entry, &std::sync::atomic::AtomicBool::new(false))
            .map(Cow::Owned)
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let record = self.record(entry)?;
        if let [s] = record.segments.as_slice() {
            return Ok(Cow::Borrowed(self.view.slice(s.offset, s.stored)?));
        }
        let mut out = Vec::new();
        for s in &record.segments {
            out.extend_from_slice(self.view.slice(s.offset, s.stored)?);
        }
        Ok(Cow::Owned(out))
    }
}
nvlens_core::register_archive!(Xp3);

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::{
        XChaCha20Poly1305,
        aead::{AeadInPlace, KeyInit},
    };
    use nvlens_core::Secret;
    use nvlens_io::BinaryWriter;
    use std::{
        fs,
        io::Write,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
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
                "nvlens-hxv4-{}-{stamp}-{}.xp3",
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
        use nvlens_crypto::hash::hxv4 as hashes;
        use std::sync::atomic::AtomicBool;
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
        write(&source.path,&[(hashed("","startup.tjs"),br#"var a="scenario/"+"chapter/first.ks"; var b="image/bg.png"; var c="prefix"+unknown+"suffix.png";"#)])?;
        write(
            &images.path,
            &[
                (first.clone(), b"@image storage=image/bg.png"),
                (hashed("image/", "bg.png"), b"\x89PNG\r\n\x1a\n\0\0"),
                (missing.clone(), b"\0\x01"),
                (hashed("", "bad.ks"), b"\xfe\xfe"),
            ],
        )?;
        let cancel = AtomicBool::new(false);
        let mut recovery = NameRecovery::open(
            &[
                (images.path.clone(), ArchiveOptions::default()),
                (source.path.clone(), ArchiveOptions::default()),
            ],
            &cancel,
        )?;
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
        assert_eq!(original.entries()[0].name, first);
        assert_eq!(recovery.progress().failed, 1);
        assert_eq!(recovery.take_errors().len(), 1);
        assert!(recovery.take_errors().is_empty());
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
        nvlens_crypto::cipher::xp3::xor31(hash, 0, &mut cipher);
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
            path: std::env::temp_dir()
                .join(format!("nvlens-xor31-{}-{stamp}.xp3", std::process::id())),
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
}
