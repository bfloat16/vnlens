//! KiriKiri XP3. XP3Archive.cpp uses LE chunk lengths and segment
//! descriptors; Hxv4 adds an out-of-line tag-prefix XChaCha20-Poly1305 table.
//! Mounting reads only the standard and optional Hxv4 indices. Entry segments are inflated then filtered
//! at their logical offsets and checked against the plaintext Adler-32.
mod names;
mod read;
mod special;
pub use names::{NameProgress, NameRecovery};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use vnlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, Packed, ResourceKind, Result,
};
use vnlens_crypto::{
    checksum::adler32,
    cipher::hxv4::{self, Filter},
    compress::zlib,
};
use vnlens_io::{ArcView, BinaryReader};
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    names: BTreeMap<String, BTreeMap<(u64, u64), usize>>,
    filter: Option<Arc<Filter>>,
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
            Some(Arc::new(
                Filter::from_params_and_table(key(options, "hxv4_params")?, &words)
                    .map_err(|e| Error::UnknownScheme(Some(e)))?
                    .with_holder_words(
                        BinaryReader::u32_le(nonce),
                        BinaryReader::u32_le(&nonce[4..]),
                    ),
            ))
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
                    kind: ResourceKind::Unknown,
                    name: path,
                    offset: begin,
                    size: end - begin,
                    packed: Some(packed),
                };
                // Hxv4 can assign several synthetic IDs to the same hashed
                // path and physical segments. Keep every index entry, and
                // distinguish repeated paths by their actual storage extent.
                let identity = (entry.offset, entry.size);
                let ranges = names
                    .entry(entry.name.clone())
                    .or_insert_with(BTreeMap::new);
                if let Some(&previous) = ranges.get(&identity) {
                    let old: &Record = &selected[previous];
                    if old.flags != record.flags
                        || old.size != record.size
                        || old.stored != record.stored
                        || old.segments != record.segments
                        || old.adler != record.adler
                        || old.filter != record.filter
                    {
                        return Err(corrupt(
                            begin,
                            "Conflicting XP3 metadata for identical entry storage",
                        ));
                    }
                } else {
                    ranges.insert(identity, selected.len());
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
                        return Err(vnlens_io::BinaryIo::unexpected_eof(
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
            .and_then(|ranges| ranges.get(&(entry.offset, entry.size)))
            .map(|&i| &self.records[i])
            .ok_or_else(|| corrupt(entry.offset, "Entry does not belong to this XP3"))
    }
}
impl Archive for Xp3Archive {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn vnlens_io::ReadAt>>> {
        Ok(Some(self.source(entry)?))
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
vnlens_core::register_archive!(Xp3);

#[cfg(test)]
#[path = "../../tests/krkr/mod.rs"]
mod tests;
