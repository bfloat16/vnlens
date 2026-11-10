//! YPF 0x1EE, verified against client index reader 0x45EC64 and entry reader
//! 0x43F0C8. The header's index end includes its 0x20 bytes. Records contain
//! MurmurHash2 name hashes, substituted name lengths, XOR names, type/packing,
//! unpacked/stored lengths, a 64-bit file offset, and a stored-byte hash.

use std::borrow::Cow;
use std::sync::Arc;
use vnlens_core::{ArcView, Archive, Entry, Error, Packed, ResourceKind, Result};
use vnlens_crypto::{compress::zlib, hash::murmur2};
use vnlens_io::BinaryReader;

// Client 0x46327C constructs this involution before decoding index lengths.
const LENGTH_SWAPS: &[(u8, u8)] = &[
    (3, 72),
    (6, 53),
    (9, 11),
    (12, 16),
    (13, 19),
    (17, 25),
    (21, 27),
    (28, 30),
    (32, 35),
    (38, 41),
    (44, 47),
    (46, 50),
];

pub(super) struct YpfArchive {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
    checksums: Vec<u32>,
    script_key: [u8; 4],
}

impl std::fmt::Debug for YpfArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YpfArchive")
            .field("view", &self.view)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl YpfArchive {
    pub(super) fn open(view: Arc<ArcView>, script_key: [u8; 4], name_key: u8) -> Result<Self> {
        let header = view.slice(0, 32)?;
        let version = BinaryReader::u32_le(&header[4..]);
        if version != 0x1ee {
            return Err(Error::Unsupported(format!("YPF version 0x{version:X}")));
        }
        let count = BinaryReader::u32_le(&header[8..]) as usize;
        let index_end = u64::from(BinaryReader::u32_le(&header[12..]));
        let index_size = index_end
            .checked_sub(32)
            .ok_or_else(|| corrupt(12, "Index end precedes header"))?;
        let index = view.slice(32, index_size)?;
        if count > index.len() / 27 {
            return Err(corrupt(8, "Entry count exceeds index record capacity"));
        }
        let mut reader = BinaryReader::new(index);
        let mut entries = Vec::with_capacity(count);
        let mut checksums = Vec::with_capacity(count);
        for _ in 0..count {
            let record_offset = reader.position() as u64 + 32;
            let hash = reader.read_u32_le()?;
            let mut length = !reader.read_u8()?;
            for &(left, right) in LENGTH_SWAPS {
                if length == left {
                    length = right;
                    break;
                }
                if length == right {
                    length = left;
                    break;
                }
            }
            let encoded = reader.read_bytes(usize::from(length))?;
            let name_bytes: Vec<_> = encoded.iter().map(|&b| b ^ name_key).collect();
            if murmur2::hash(&name_bytes, 0) != hash {
                return Err(corrupt(record_offset, "Filename hash mismatch"));
            }
            let name = encoding_rs::SHIFT_JIS
                .decode_without_bom_handling_and_without_replacement(&name_bytes)
                .ok_or_else(|| corrupt(record_offset, "Invalid CP932 filename"))?
                .into_owned();
            let file_type = reader.read_u8()?;
            let packing = reader.read_u8()?;
            if packing > 1 {
                return Err(Error::Unsupported(format!(
                    "YPF compression method {packing}"
                )));
            }
            let unpacked_size = u64::from(reader.read_u32_le()?);
            let size = u64::from(reader.read_u32_le()?);
            let offset = reader.read_u64_le()?;
            checksums.push(reader.read_u32_le()?);
            // Preserve the index's resource class. Engine routing resolves
            // filename and content variants only when the entry is accessed.
            let kind = match file_type {
                0 => ResourceKind::Script,
                1..=4 | 7..=9 => ResourceKind::Image,
                5 | 6 => ResourceKind::Audio,
                _ => ResourceKind::Unknown,
            };
            let entry = Entry {
                name,
                kind,
                offset,
                size,
                packed: Some(Packed {
                    unpacked_size,
                    is_packed: packing == 1,
                }),
            };
            if offset < index_end || !entry.check_placement(view.len()) {
                return Err(corrupt(
                    record_offset,
                    "Entry range lies outside the payload area",
                ));
            }
            if packing == 0 && size != unpacked_size {
                return Err(corrupt(record_offset, "Stored entry lengths disagree"));
            }
            entries.push(entry);
        }
        if reader.remaining() != 0 {
            return Err(corrupt(
                32 + reader.position() as u64,
                "Unexpected bytes after index records",
            ));
        }
        Ok(Self {
            view,
            entries,
            checksums,
            script_key,
        })
    }
}

impl YpfArchive {
    fn index(&self, entry: &Entry) -> Result<usize> {
        self.entries
            .iter()
            .position(|candidate| std::ptr::eq(candidate, entry))
            .or_else(|| {
                self.entries.iter().position(|candidate| {
                    candidate.offset == entry.offset
                        && candidate.name == entry.name
                        && candidate.size == entry.size
                })
            })
            .ok_or_else(|| corrupt(entry.offset, "Entry does not belong to this YPF"))
    }
}

impl Archive for YpfArchive {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn vnlens_io::ReadAt>>> {
        let index = self.index(entry)?;
        if entry
            .name
            .rsplit('.')
            .next()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("ybn"))
        {
            return Ok(None);
        }
        Ok(Some(Arc::new(super::stream::YpfSource {
            source: Arc::new(vnlens_io::RangeSource::new(
                self.view.clone(),
                entry.offset,
                entry.size,
            )?),
            packed: entry.packed.is_some_and(|packed| packed.is_packed),
            size: entry
                .packed
                .map_or(entry.size, |packed| packed.unpacked_size),
            checksum: self.checksums[index],
            offset: entry.offset,
        })))
    }
    fn virtual_paths(&self) -> Result<Vec<(usize, String)>> {
        let Some(table) = self.entries.iter().find(|entry| {
            entry
                .name
                .replace('\\', "/")
                .eq_ignore_ascii_case("ysbin/yst_list.ybn")
        }) else {
            return Ok(Vec::new());
        };
        let data = self.open_entry(table)?;
        let paths = vnlens_script::yuris::script_paths(&data)?;
        let indices: std::collections::HashMap<_, _> = self
            .entries
            .iter()
            .enumerate()
            .map(|(index, entry)| (entry.name.replace('\\', "/").to_ascii_lowercase(), index))
            .collect();
        Ok(paths
            .into_iter()
            .filter_map(|(id, path)| {
                indices
                    .get(&format!("ysbin/yst{id:05}.ybn"))
                    .filter(|_| !path.is_empty())
                    .map(|&index| (index, path))
            })
            .collect())
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let index = self.index(entry)?;
        let stored = self.view.slice(entry.offset, entry.size)?;
        if murmur2::hash(stored, 0) != self.checksums[index] {
            return Err(corrupt(entry.offset, "Stored payload hash mismatch"));
        }
        let packed = self.entries[index].packed;
        let mut bytes = if let Some(packed) = packed.filter(|p| p.is_packed) {
            let expected = usize::try_from(packed.unpacked_size)
                .map_err(|_| corrupt(entry.offset, "Decoded length exceeds address space"))?;
            let decoded = zlib::inflate_with_limit(stored, expected)
                .map_err(|e| corrupt(entry.offset, &e.to_string()))?;
            if decoded.len() != expected {
                return Err(corrupt(entry.offset, "Decompressed length mismatch"));
            }
            Cow::Owned(decoded)
        } else {
            Cow::Borrowed(stored)
        };
        if bytes.starts_with(b"YSTB") {
            vnlens_script::yuris::decrypt_ystb(bytes.to_mut(), &self.script_key)?;
        }
        Ok(bytes)
    }
}

fn corrupt(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "../../tests/yuris/ypf.rs"]
mod tests;
