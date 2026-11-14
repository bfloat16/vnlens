//! PFS0: 0x10 header, 0x18 records, UTF-8 name table, then payloads.
//! HFS0 records are 0x40 bytes and include a hashed subrange and SHA-256.
//! XCI HEAD lives at 0x100 (or 0x1100 with initial data); root HFS0 is
//! addressed relative to the card body. Certificate/header encryption is not
//! needed to read its filesystem index.
use super::integrity::{RegionHash, hash_range};
use super::{FileSystem, add, bounds, corrupt, memory, name, range};
use std::sync::Arc;
use vnlens_core::{Entry, Error, ResourceKind, Result};
use vnlens_io::{BinaryReader, ReadAt};

/// Parses exactly the selected partition kind, without inspecting payloads.
pub fn open_partition(source: Arc<dyn ReadAt>, hashed: bool) -> Result<FileSystem> {
    let header = source.read_at(0, 16)?;
    let magic: &[u8] = if hashed { b"HFS0" } else { b"PFS0" };
    if &header[..4] != magic {
        return Err(Error::InvalidFormat);
    }
    let count = u64::from(BinaryReader::u32_le(&header[4..8]));
    let strings_size = u64::from(BinaryReader::u32_le(&header[8..12]));
    let record_size = if hashed { 64 } else { 24 };
    let records_size = count
        .checked_mul(record_size)
        .ok_or_else(|| corrupt(4, "Partition record size overflow"))?;
    let strings_offset = add(16, records_size)?;
    let data_offset = add(strings_offset, strings_size)?;
    bounds(source.as_ref(), 0, data_offset)?;
    let records = source.read_at(16, memory(records_size)?)?;
    let strings = source.read_at(strings_offset, memory(strings_size)?)?;
    let mut entries = Vec::new();
    let mut hashes = Vec::new();
    for (index, record) in records.chunks_exact(record_size as usize).enumerate() {
        let relative = BinaryReader::u64_le(&record[..8]);
        let size = BinaryReader::u64_le(&record[8..16]);
        let name_offset = BinaryReader::u32_le(&record[16..20]) as usize;
        let suffix = strings
            .get(name_offset..)
            .ok_or_else(|| corrupt(strings_offset, "Partition filename offset exceeds table"))?;
        let end = suffix.iter().position(|&b| b == 0).ok_or_else(|| {
            corrupt(
                strings_offset + name_offset as u64,
                "Unterminated partition filename",
            )
        })?;
        let offset = add(data_offset, relative)?;
        bounds(source.as_ref(), offset, size)?;
        entries.push(Entry {
            name: name(&suffix[..end], strings_offset + name_offset as u64)?,
            kind: ResourceKind::Unknown,
            offset,
            size,
            packed: None,
        });
        if hashed {
            let hashed_size = u64::from(BinaryReader::u32_le(&record[20..24]));
            let hashed_offset = BinaryReader::u64_le(&record[24..32]);
            if hashed_offset > size || hashed_size > size - hashed_offset {
                return Err(corrupt(
                    16 + index as u64 * record_size,
                    "HFS0 hash range exceeds entry",
                ));
            }
            hashes.push(Some(RegionHash {
                offset: hashed_offset,
                size: hashed_size,
                expected: record[32..64]
                    .try_into()
                    .map_err(|_| Error::InvalidFormat)?,
            }));
        }
    }
    drop(records);
    drop(strings);
    Ok(FileSystem {
        entries,
        source,
        hashes,
    })
}

/// Opens an XCI's root index. Nested partition bodies stay unopened.
pub fn open_xci(source: Arc<dyn ReadAt>) -> Result<FileSystem> {
    let base = if source.len() >= 0x1104 && source.read_at(0x1100, 4)?.as_ref() == b"HEAD" {
        0x1000
    } else {
        0
    };
    let header = source.read_at(base + 0x100, 0x100)?;
    if &header[..4] != b"HEAD" {
        return Err(Error::InvalidFormat);
    }
    let root = add(base, BinaryReader::u64_le(&header[0x30..0x38]))?;
    let header_size = BinaryReader::u64_le(&header[0x38..0x40]);
    bounds(source.as_ref(), root, header_size)?;
    let expected: [u8; 32] = header[0x40..0x60]
        .try_into()
        .map_err(|_| Error::InvalidFormat)?;
    // CompatibilityType 0 is the standard XCI root hash. Other card types
    // append a byte from the encrypted card header and require that header key.
    let actual = hash_range(source.as_ref(), root, header_size, header_size)?;
    if actual != expected {
        return Err(corrupt(root, "XCI root partition SHA-256 mismatch"));
    }
    let root_source = range(source.clone(), root, source.len() - root)?;
    let mut fs = open_partition(root_source, true)?;
    // Expose original file offsets, including the optional initial-data area.
    for entry in &mut fs.entries {
        entry.offset = add(root, entry.offset)?;
        entry.kind = ResourceKind::Archive;
    }
    fs.source = source;
    Ok(fs)
}
