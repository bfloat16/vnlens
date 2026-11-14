//! NcaCompressionInfo and Atmosphere CompressedStorage::Entry layout: a BKTR
//! index with 0x18-byte records maps logical ranges to plain, zero or raw LZ4
//! blocks. Compression wraps the authenticated filesystem data, not its hashes.
use super::{bounds, corrupt, memory, range};
use std::{borrow::Cow, io, sync::Arc};
use vnlens_core::{Error, Result};
use vnlens_io::{BinaryIo, BinaryReader, ReadAt};

struct Block {
    offset: u64,
    physical: u64,
    size: usize,
    kind: u8,
}
struct Compressed {
    source: Arc<dyn ReadAt>,
    blocks: Vec<Block>,
    size: u64,
}

pub(super) fn open(
    source: Arc<dyn ReadAt>,
    fs: &[u8],
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<Arc<dyn ReadAt>> {
    super::check_cancel(cancel)?;
    let offset = BinaryReader::u64_le(&fs[0x178..]);
    let size = BinaryReader::u64_le(&fs[0x180..]);
    if size == 0 {
        return Ok(source);
    }
    let index = range(source.clone(), offset, size)?;
    let table = super::patch::table(index.as_ref(), &fs[0x188..0x198], 24, cancel)?;
    let source = range(source, 0, offset)?;
    let mut blocks = Vec::new();
    for (i, row) in table.entries.iter().enumerate() {
        super::check_cancel(cancel)?;
        let virtual_at = BinaryReader::u64_le(row);
        let physical = BinaryReader::u64_le(&row[8..]);
        let kind = row[16];
        // phys_size is meaningful only for compressed entries. Plain and zero
        // entries use their virtual extent and may store -1 in this field.
        let size = if kind == 3 {
            usize::try_from(BinaryReader::u32_le(&row[20..]) as i32)
                .map_err(|_| corrupt(offset, "Negative NCA compressed block size"))?
        } else {
            0
        };
        let end = table
            .entries
            .get(i + 1)
            .map_or(table.end, |next| BinaryReader::u64_le(next));
        if i == 0 && virtual_at != 0 {
            return Err(corrupt(
                offset,
                "NCA compression map does not start at zero",
            ));
        }
        match kind {
            0 => bounds(source.as_ref(), physical, end - virtual_at)?,
            1 => {}
            3 => {
                if !physical.is_multiple_of(16) || size == 0 {
                    return Err(corrupt(offset, "Invalid NCA LZ4 block range"));
                }
                bounds(source.as_ref(), physical, size as u64)?;
            }
            other => return Err(Error::Unsupported(format!("NCA compression type {other}"))),
        }
        blocks.push(Block {
            offset: virtual_at,
            physical,
            size,
            kind,
        });
    }
    Ok(Arc::new(Compressed {
        source,
        blocks,
        size: table.end,
    }))
}

impl ReadAt for Compressed {
    fn len(&self) -> u64 {
        self.size
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        if offset > self.size || size as u64 > self.size - offset {
            return Err(BinaryIo::unexpected_eof(
                "NCA compressed read exceeds logical size",
            ));
        }
        let mut output = Vec::new();
        let mut position = offset;
        while output.len() < size {
            let index = self
                .blocks
                .partition_point(|block| block.offset <= position)
                .checked_sub(1)
                .ok_or_else(|| io::Error::other("Missing NCA compression mapping"))?;
            let block = &self.blocks[index];
            let end = self
                .blocks
                .get(index + 1)
                .map_or(self.size, |block| block.offset);
            let take = (end - position).min((size - output.len()) as u64) as usize;
            match block.kind {
                0 => {
                    let bytes = self
                        .source
                        .read_at(block.physical + (position - block.offset), take)?;
                    if take == size {
                        return Ok(bytes);
                    }
                    output.extend_from_slice(&bytes);
                }
                1 => output.resize(output.len() + take, 0),
                _ => {
                    let compressed = self.source.read_at(block.physical, block.size)?;
                    let logical = memory(end - block.offset).map_err(io::Error::other)?;
                    let decoded = vnlens_crypto::compress::lz4::decompress(&compressed, logical)?;
                    let start = (position - block.offset) as usize;
                    output.extend_from_slice(&decoded[start..start + take]);
                }
            }
            position += take as u64;
        }
        Ok(Cow::Owned(output))
    }
}

#[cfg(test)]
#[path = "../../tests/ns/compression.rs"]
mod tests;
