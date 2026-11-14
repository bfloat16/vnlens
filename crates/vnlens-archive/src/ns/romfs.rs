//! Switch RomFS 0x50 header; directory/file metadata stores linked u32
//! offsets, 0xffffffff terminators, and UTF-8 names. File ranges are relative
//! to the data area. Traversal uses actual links and rejects repeated nodes.
use super::{FileSystem, add, bounds, corrupt, memory, name, range};
use std::{collections::HashSet, sync::Arc};
use vnlens_core::{Entry, Error, ResourceKind, Result};
use vnlens_io::{BinaryReader, ReadAt};

pub fn open_romfs(source: Arc<dyn ReadAt>) -> Result<FileSystem> {
    let header = source.read_at(0, 0x50)?;
    if BinaryReader::u64_le(&header[..8]) != 0x50 {
        return Err(Error::InvalidFormat);
    }
    let mut fields = Vec::new();
    for field in header[8..].as_chunks::<8>().0 {
        fields.push(BinaryReader::u64_le(field));
    }
    for pair in fields[..8].as_chunks::<2>().0 {
        bounds(source.as_ref(), pair[0], pair[1])?;
    }
    bounds(source.as_ref(), fields[8], 0)?;
    let directories = range(source.clone(), fields[2], fields[3])?;
    let files = range(source.clone(), fields[6], fields[7])?;
    let mut pending = vec![(0u32, String::new(), 0u32)];
    let mut visited_dirs = HashSet::new();
    let mut visited_files = HashSet::new();
    let mut entries = Vec::new();
    while let Some((index, prefix, parent)) = pending.pop() {
        if index == u32::MAX {
            continue;
        }
        if !visited_dirs.insert(index) {
            return Err(corrupt(
                u64::from(index),
                "Cyclic or shared RomFS directory link",
            ));
        }
        let record = directories.read_at(u64::from(index), 24)?;
        if BinaryReader::u32_le(&record[..4]) != parent {
            return Err(corrupt(u64::from(index), "RomFS directory parent mismatch"));
        }
        let sibling = BinaryReader::u32_le(&record[4..8]);
        let child = BinaryReader::u32_le(&record[8..12]);
        let mut file = BinaryReader::u32_le(&record[12..16]);
        let length = BinaryReader::u32_le(&record[20..24]);
        let component = directories.read_at(u64::from(index) + 24, memory(u64::from(length))?)?;
        let component = name(&component, u64::from(index) + 24)?;
        let path = if index == 0 {
            prefix.clone()
        } else if prefix.is_empty() {
            component
        } else {
            format!("{prefix}/{component}")
        };
        if index != 0 {
            pending.push((sibling, prefix, parent));
        }
        pending.push((child, path.clone(), index));
        while file != u32::MAX {
            if !visited_files.insert(file) {
                return Err(corrupt(u64::from(file), "Cyclic or shared RomFS file link"));
            }
            let record = files.read_at(u64::from(file), 32)?;
            if BinaryReader::u32_le(&record[..4]) != index {
                return Err(corrupt(u64::from(file), "RomFS file parent mismatch"));
            }
            let next = BinaryReader::u32_le(&record[4..8]);
            let offset = add(fields[8], BinaryReader::u64_le(&record[8..16]))?;
            let size = BinaryReader::u64_le(&record[16..24]);
            bounds(source.as_ref(), offset, size)?;
            let length = BinaryReader::u32_le(&record[28..32]);
            let bytes = files.read_at(u64::from(file) + 32, memory(u64::from(length))?)?;
            let leaf = name(&bytes, u64::from(file) + 32)?;
            entries.push(Entry {
                name: if path.is_empty() {
                    leaf
                } else {
                    format!("{path}/{leaf}")
                },
                kind: ResourceKind::Unknown,
                offset,
                size,
                packed: None,
            });
            file = next;
        }
    }
    Ok(FileSystem {
        entries,
        source,
        hashes: Vec::new(),
    })
}
