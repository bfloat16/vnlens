//! AFS2 (AWB): LE header, variable-width wave IDs and N+1 absolute offsets.
//! Align each start; the following unaligned offset is the preceding file end.
//! The header's subkey is retained for HCA key derivation by the caller.
use super::{add, bounds, corrupt, cpk::align, memory, range};
use std::{borrow::Cow, sync::Arc};
use vnlens_core::{Entry, Error, ResourceKind, Result};
use vnlens_io::{BinaryReader, ReadAt};

pub struct Awb {
    pub version: u8,
    pub subkey: u16,
    pub ids: Vec<u64>,
    pub entries: Vec<Entry>,
    source: Arc<dyn ReadAt>,
}
impl std::fmt::Debug for Awb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Awb")
            .field("version", &self.version)
            .field("entries", &self.entries)
            .finish_non_exhaustive()
    }
}
impl Awb {
    pub fn open(source: Arc<dyn ReadAt>) -> Result<Self> {
        let header = source.read_at(0, 16)?;
        if &header[..4] != b"AFS2" {
            return Err(Error::InvalidFormat);
        }
        let version = header[4];
        let offset_width = usize::from(header[5]);
        let id_width = usize::from(BinaryReader::u16_le(&header[6..8]));
        if !matches!(offset_width, 1 | 2 | 4 | 8) || !matches!(id_width, 1 | 2 | 4 | 8) {
            return Err(Error::Unsupported("AWB integer field width".into()));
        }
        let count = u64::from(BinaryReader::u32_le(&header[8..12]));
        let alignment = u64::from(BinaryReader::u16_le(&header[12..14]));
        let subkey = BinaryReader::u16_le(&header[14..16]);
        if alignment == 0 {
            return Err(corrupt(12, "AWB alignment is zero"));
        }
        let ids_size = count * id_width as u64;
        let offsets_size = (count + 1) * offset_width as u64;
        let index_end = add(add(16, ids_size)?, offsets_size)?;
        bounds(source.as_ref(), 0, index_end)?;
        let index = source.read_at(16, memory(ids_size + offsets_size)?)?;
        let ids = index[..memory(ids_size)?]
            .chunks_exact(id_width)
            .map(BinaryReader::compact_u64_le)
            .collect::<std::io::Result<Vec<_>>>()?;
        let offsets = index[memory(ids_size)?..]
            .chunks_exact(offset_width)
            .map(BinaryReader::compact_u64_le)
            .collect::<std::io::Result<Vec<_>>>()?;
        let mut entries = Vec::new();
        for (i, &id) in ids.iter().enumerate() {
            let start = align(offsets[i], alignment)?;
            let end = offsets[i + 1];
            if start < index_end || end < start {
                return Err(corrupt(start, "Invalid AWB file offset ordering"));
            }
            bounds(source.as_ref(), start, end - start)?;
            entries.push(Entry {
                name: id.to_string(),
                kind: ResourceKind::Audio,
                offset: start,
                size: end - start,
                packed: None,
            });
        }
        drop(index);
        drop(header);
        Ok(Self {
            version,
            subkey,
            ids,
            entries,
            source,
        })
    }
    pub fn read(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(self.source.read_at(entry.offset, memory(entry.size)?)?)
    }
    pub fn source(&self, entry: &Entry) -> Result<Arc<dyn ReadAt>> {
        range(self.source.clone(), entry.offset, entry.size)
    }
}

#[cfg(test)]
#[path = "../../tests/criware/awb.rs"]
mod tests;
