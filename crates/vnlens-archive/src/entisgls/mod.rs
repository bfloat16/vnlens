//! ERISA-Archive / EMSAC-Binary Archive: a 64-byte LE file header followed
//! by DirEntry sections. Index records store logical length, attributes,
//! transformation, signed directory-relative record offset, timestamp, extra bytes
//! and a length-prefixed terminated name. UTF-8 is selected by attribute
//! 0x01000000; classic names use CP932. Filedata record headers are necessary
//! storage metadata because compressed sizes are absent from DirEntry.
//! Verified against ERISAArchive sub_4AF2D0 / sub_4AE4D0 and SakuraGL
//! SGLArchiveFile sub_62FFE0. Mounting never consumes filedata payloads.

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashSet},
    io::{self, Read},
    sync::Arc,
};
use vnlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, Packed, ResourceKind, Result,
};
use vnlens_crypto::compress::erisa::NemesisDecoder;
use vnlens_io::{
    ArcView, BinaryIo, BinaryReader, BinarySourceReader, RangeSource, ReadAt, ReplaySource,
};

const SIGNATURES: &[u32] = &[0x6974_6e45, 0x5453_4956];

#[derive(Debug, Default)]
struct Noa;
impl Format for Noa {
    fn tag(&self) -> &'static str {
        "noa/entisgls"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["noa"]
    }
    fn description(&self) -> &'static str {
        "EntisGLS ERISA resource archive"
    }
}

impl ArchiveFormat for Noa {
    fn open(&self, view: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        Ok(Box::new(Pack::open(view.clone())?))
    }
    fn open_source(
        &self,
        source: Arc<dyn ReadAt>,
        _: &str,
        _: &ArchiveOptions,
    ) -> Result<Option<Box<dyn Archive>>> {
        Ok(Some(Box::new(Pack::open(source)?)))
    }
}
impl Pack {
    fn open(source: Arc<dyn ReadAt>) -> Result<Self> {
        let head = source.read_at(0, 64)?;
        if !(head.starts_with(b"Entis\x1a\0\0") || head.starts_with(b"VIST\x1a\0\0\0")) {
            return Err(bad(0, "Invalid ERISA archive signature"));
        }
        if BinaryReader::u32_le(&head[8..12]) != 0x0200_0400 {
            return Err(Error::Unsupported("ERISA archive file identity".into()));
        }
        if !(head[16..].starts_with(b"ERISA-Archive file\0")
            || head[16..].starts_with(b"EMSAC-Binary Archive\0"))
        {
            return Err(bad(16, "Invalid ERISA archive description"));
        }
        let mut entries = Vec::new();
        let mut storage = BTreeMap::new();
        let mut directories = vec![(64, String::new(), false)];
        let mut visited = HashSet::new();
        while let Some((base, prefix, leave)) = directories.pop() {
            if leave {
                visited.remove(&base);
                continue;
            }
            if !visited.insert(base) {
                return Err(bad(base, "Cyclic ERISA directory reference"));
            }
            directories.push((base, String::new(), true));
            let (id, start, size) = section(source.as_ref(), base)?;
            if id != *b"DirEntry" {
                return Err(bad(base, "Missing ERISA DirEntry"));
            }
            let index = RangeSource::new(source.clone(), start, size)?;
            let mut r = BinarySourceReader::new(&index);
            let count = r.read_u32_le()?;
            for _ in 0..count {
                let at = start + r.position() as u64;
                let logical = r.read_u64_le()?;
                let attr = r.read_u32_le()?;
                let encoding = r.read_u32_le()?;
                let relative = r.read_u64_le()? as i64;
                r.read_u64_le()?; // FILE_TIME
                let extra_len = usize::try_from(r.read_u32_le()?).map_err(io::Error::other)?;
                r.skip(extra_len)?;
                let name_len = usize::try_from(r.read_u32_le()?).map_err(io::Error::other)?;
                let name_bytes = r.read_bytes(name_len)?;
                if attr & 0x0100_0000 != 0 && name_bytes.last() != Some(&0) {
                    return Err(bad(at, "Unterminated ERISA UTF-8 entry name"));
                }
                // Classic ERISA appends a terminator after the length-delimited
                // buffer; SGL also requires a stored final terminator. Both use
                // the first NUL as the end of the filename.
                let name_bytes = name_bytes.split(|&b| b == 0).next().unwrap_or_default();
                let name = if attr & 0x0100_0000 != 0 {
                    std::str::from_utf8(name_bytes)
                        .map_err(|_| bad(at, "Invalid ERISA UTF-8 name"))?
                        .to_owned()
                } else {
                    let (text, _, errors) = encoding_rs::SHIFT_JIS.decode(name_bytes);
                    if errors {
                        return Err(bad(at, "Invalid ERISA CP932 name"));
                    }
                    text.into_owned()
                };
                let path = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                if matches!(attr & 0x70, 0x20 | 0x40) {
                    // Parent/self directory records do not contribute resources.
                    continue;
                }
                let offset = base
                    .checked_add_signed(relative)
                    .ok_or_else(|| bad(at + 16, "ERISA record offset overflow"))?;
                let (id, payload, stored) = section(source.as_ref(), offset)?;
                if attr & 0x70 == 0x10 {
                    directories.push((payload, path, false));
                    continue;
                }
                if id != *b"filedata" {
                    return Err(bad(offset, "Missing ERISA filedata record"));
                }
                if encoding == 0 && stored != logical {
                    return Err(bad(offset + 8, "ERISA stored and logical sizes differ"));
                }
                if encoding != 0 && stored < 4 {
                    return Err(bad(offset + 8, "ERISA transformed record lacks checksum"));
                }
                if let Some(&(previous, length)) = storage.get(&payload)
                    && (previous != encoding || length != logical)
                {
                    return Err(bad(at, "Conflicting ERISA storage references"));
                }
                storage.insert(payload, (encoding, logical));
                entries.push(Entry {
                    name: path,
                    kind: ResourceKind::Unknown,
                    offset: payload,
                    size: stored,
                    packed: (encoding != 0).then_some(Packed {
                        unpacked_size: logical,
                        is_packed: encoding & 0x8000_0000 != 0,
                    }),
                });
            }
        }
        Ok(Self {
            source,
            entries,
            storage,
        })
    }
}

struct Pack {
    source: Arc<dyn ReadAt>,
    entries: Vec<Entry>,
    storage: BTreeMap<u64, (u32, u64)>,
}

impl std::fmt::Debug for Pack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pack")
            .field("entries", &self.entries.len())
            .field("size", &self.source.len())
            .finish_non_exhaustive()
    }
}

impl Archive for Pack {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let (encoding, logical) = self
            .storage
            .get(&entry.offset)
            .copied()
            .ok_or_else(|| bad(entry.offset, "Unknown ERISA entry"))?;
        if encoding == 0 {
            return Ok(self.source.read_at(
                entry.offset,
                usize::try_from(entry.size).map_err(io::Error::other)?,
            )?);
        }
        let source = self
            .open_entry_source(entry)?
            .ok_or_else(|| Error::Unsupported(format!("ERISA transformation 0x{encoding:08X}")))?;
        let size = usize::try_from(logical).map_err(io::Error::other)?;
        let bytes = source.read_at(0, size).map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidData {
                bad(
                    entry.offset,
                    &format!("ERISA entry {}: {error}", entry.name),
                )
            } else {
                Error::Io(error)
            }
        })?;
        Ok(Cow::Owned(bytes.into_owned()))
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn ReadAt>>> {
        let (encoding, logical) = self
            .storage
            .get(&entry.offset)
            .copied()
            .ok_or_else(|| bad(entry.offset, "Unknown ERISA entry"))?;
        if encoding == 0 {
            return Ok(Some(Arc::new(RangeSource::new(
                self.source.clone(),
                entry.offset,
                entry.size,
            )?)));
        }
        if encoding != 0x8000_0010 {
            if encoding & 0x6000_0000 != 0 {
                return Err(Error::UnknownScheme(Some(
                    "EntisGLS archive entry key was not resolved".into(),
                )));
            }
            return Err(Error::Unsupported(format!(
                "ERISA transformation 0x{encoding:08X}"
            )));
        }
        let source = Arc::new(RangeSource::new(
            self.source.clone(),
            entry.offset,
            entry
                .size
                .checked_sub(4)
                .ok_or_else(|| bad(entry.offset, "ERISA transformed record lacks checksum"))?,
        )?);
        let check_at = entry
            .offset
            .checked_add(entry.size)
            .and_then(|v| v.checked_sub(4))
            .ok_or_else(|| bad(entry.offset, "ERISA checksum range overflow"))?;
        let check = self.source.read_at(check_at, 4)?;
        let expected = [check[0], check[1], check[2], check[3]];
        let factory = Arc::new(move |cancel| {
            let reader = source.clone().reader(cancel)?;
            let decoder = NemesisDecoder::new(std::io::BufReader::new(reader))?;
            Ok(Box::new(Checked {
                decoder,
                remaining: logical,
                expected,
                checksum: [0; 4],
                lane: 0,
                finished: false,
            }) as Box<dyn Read + Send>)
        });
        Ok(Some(Arc::new(ReplaySource::new(factory, logical)?)))
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(self.source.read_at(
            entry.offset,
            usize::try_from(entry.size).map_err(io::Error::other)?,
        )?)
    }
}

struct Checked<R> {
    decoder: NemesisDecoder<R>,
    remaining: u64,
    expected: [u8; 4],
    checksum: [u8; 4],
    lane: usize,
    finished: bool,
}
impl<R: Read> Read for Checked<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            if !self.finished {
                if self.checksum != self.expected {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ERISA checksum mismatch",
                    ));
                }
                self.finished = true;
            }
            return Ok(0);
        }
        let size = out
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let count = self.decoder.read(&mut out[..size])?;
        if count == 0 {
            return Err(BinaryIo::unexpected_eof(
                "ERISA output ends before logical size",
            ));
        }
        self.remaining -= count as u64;
        for &byte in &out[..count] {
            self.checksum[self.lane] ^= byte;
            self.lane = (self.lane + 1) & 3;
        }
        Ok(count)
    }
}

fn section(source: &dyn ReadAt, at: u64) -> Result<([u8; 8], u64, u64)> {
    let bytes = source.read_at(at, 16)?;
    let mut r = BinaryReader::new(&bytes);
    let mut id = [0; 8];
    id.copy_from_slice(r.read_bytes(8)?);
    let size = r.read_u64_le()?;
    let start = at
        .checked_add(16)
        .ok_or_else(|| bad(at, "ERISA section offset overflow"))?;
    if start > source.len() || size > source.len() - start {
        return Err(BinaryIo::unexpected_eof("ERISA section exceeds archive").into());
    }
    Ok((id, start, size))
}
fn bad(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

vnlens_core::register_archive!(Noa);

#[cfg(test)]
#[path = "../../tests/entisgls/mod.rs"]
mod tests;
