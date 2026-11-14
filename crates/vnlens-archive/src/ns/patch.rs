//! NCA BKTR records and lazy mapped reads. Layout references are Atmosphere's
//! BucketTree::{Header,NodeHeader,QueryNodeStorageSize}, IndirectStorage::Entry
//! and AesCtrCounterExtendedStorage::Entry/Read. This is an independent Rust
//! implementation of the on-disk layouts, not incorporated Atmosphere code.
use super::{add, bounds, corrupt, memory, range};
use std::{borrow::Cow, io, sync::Arc};
use vnlens_core::{Error, Result};
use vnlens_crypto::cipher::aes::apply_ctr128;
use vnlens_io::{BinaryIo, BinaryReader, ReadAt};

const NODE_SIZE: u64 = 0x4000;

pub(super) struct Table {
    pub entries: Vec<Vec<u8>>,
    pub end: u64,
}

pub(super) fn table(
    source: &dyn ReadAt,
    header: &[u8],
    stride: u64,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<Table> {
    super::check_cancel(cancelled)?;
    if &header[..4] != b"BKTR" {
        return Err(corrupt(0, "Invalid BKTR signature"));
    }
    if BinaryReader::u32_le(&header[4..]) > 1 {
        return Err(Error::Unsupported("Unsupported BKTR version".into()));
    }
    let count = u64::try_from(BinaryReader::u32_le(&header[8..]) as i32)
        .map_err(|_| corrupt(8, "Negative BKTR entry count"))?;
    if count == 0 {
        return Ok(Table {
            entries: Vec::new(),
            end: 0,
        });
    }
    let capacity = (NODE_SIZE - 16) / stride;
    let sets = count.div_ceil(capacity);
    let offsets = (NODE_SIZE - 16) / 8;
    let l2 = if sets <= offsets {
        0
    } else {
        let preliminary = sets.div_ceil(offsets);
        sets.checked_sub(
            offsets
                .checked_sub(preliminary - 1)
                .ok_or_else(|| corrupt(8, "BKTR node count exceeds root layout"))?,
        )
        .ok_or_else(|| corrupt(8, "Invalid BKTR node count"))?
        .div_ceil(offsets)
    };
    let node_bytes = (1 + l2)
        .checked_mul(NODE_SIZE)
        .ok_or_else(|| corrupt(8, "BKTR node size overflow"))?;
    bounds(
        source,
        0,
        add(
            node_bytes,
            sets.checked_mul(NODE_SIZE)
                .ok_or_else(|| corrupt(8, "BKTR entry size overflow"))?,
        )?,
    )?;
    let root = source.read_at(0, 16)?;
    if BinaryReader::u32_le(&root) != 0 {
        return Err(corrupt(0, "Invalid BKTR root index"));
    }
    let root_count = BinaryReader::u32_le(&root[4..]);
    if root_count == 0 || u64::from(root_count) > offsets {
        return Err(corrupt(4, "Invalid BKTR root count"));
    }
    let end = signed_offset(&root[8..], 8)?;
    let mut entries = Vec::new();
    let mut previous = None;
    for set in 0..sets {
        super::check_cancel(cancelled)?;
        let at = add(node_bytes, set * NODE_SIZE)?;
        let node = source.read_at(at, 16)?;
        let rows = u64::from(BinaryReader::u32_le(&node[4..]));
        let stop = signed_offset(&node[8..], at + 8)?;
        if u64::from(BinaryReader::u32_le(&node)) != set
            || rows == 0
            || rows > capacity
            || stop > end
        {
            return Err(corrupt(at, "Invalid BKTR entry-set header"));
        }
        let bytes = source.read_at(at + 16, memory(rows * stride)?)?;
        for row in bytes.chunks_exact(memory(stride)?) {
            super::check_cancel(cancelled)?;
            let offset = signed_offset(row, at)?;
            if previous.is_some_and(|last| offset <= last) || offset >= stop {
                return Err(corrupt(
                    at,
                    "BKTR entries are not ordered within their range",
                ));
            }
            previous = Some(offset);
            entries.push(row.to_vec());
        }
    }
    if entries.len() as u64 != count {
        return Err(corrupt(8, "BKTR record count differs from header"));
    }
    Ok(Table { entries, end })
}
fn signed_offset(bytes: &[u8], at: u64) -> Result<u64> {
    let value = BinaryReader::u64_le(bytes);
    if value > i64::MAX as u64 {
        return Err(corrupt(at, "Negative BKTR offset"));
    }
    Ok(value)
}

#[derive(Debug)]
struct Mapping {
    virtual_at: u64,
    physical_at: u64,
    storage: usize,
}
struct Indirect {
    sources: [Arc<dyn ReadAt>; 2],
    mappings: Vec<Mapping>,
    size: u64,
}
pub(super) fn indirect(
    patch: Arc<dyn ReadAt>,
    original: Option<Arc<dyn ReadAt>>,
    fs: &[u8],
    authenticated_meta: Option<Arc<dyn ReadAt>>,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<Arc<dyn ReadAt>> {
    let offset = BinaryReader::u64_le(&fs[0x100..]);
    let size = BinaryReader::u64_le(&fs[0x108..]);
    let metadata = range(
        authenticated_meta.unwrap_or_else(|| patch.clone()),
        offset,
        size,
    )?;
    let table = table(metadata.as_ref(), &fs[0x110..0x120], 20, cancelled)?;
    let mut mappings = Vec::new();
    for row in &table.entries {
        let storage = BinaryReader::u32_le(&row[16..]);
        if storage > 1 {
            return Err(corrupt(offset, "Invalid BKTR storage index"));
        }
        if storage == 0 && original.is_none() {
            return Err(Error::Unsupported(
                "NCA patch requires its CNMT-associated base content".into(),
            ));
        }
        mappings.push(Mapping {
            virtual_at: signed_offset(row, offset)?,
            physical_at: signed_offset(&row[8..], offset)?,
            storage: storage as usize,
        });
    }
    if mappings.first().is_some_and(|entry| entry.virtual_at != 0) {
        return Err(corrupt(offset, "BKTR mapping does not begin at zero"));
    }
    let sources = [
        original.unwrap_or_else(|| Arc::new(Arc::<[u8]>::from([]))),
        range(patch, 0, offset)?,
    ];
    for (index, mapping) in mappings.iter().enumerate() {
        let end = mappings
            .get(index + 1)
            .map_or(table.end, |next| next.virtual_at);
        bounds(
            sources[mapping.storage].as_ref(),
            mapping.physical_at,
            end - mapping.virtual_at,
        )?;
    }
    Ok(Arc::new(Indirect {
        sources,
        mappings,
        size: table.end,
    }))
}

/// Patch metadata has its own IVFC hierarchy outside the patched data image.
/// Its authenticated data region starts at the indirect-table offset; hash
/// layers are relative to layer_info_offset, as in CreatePatchMetaStorage.
pub(super) fn metadata(
    source: Arc<dyn ReadAt>,
    fs: &[u8],
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<Option<Arc<dyn ReadAt>>> {
    if fs[5] == 0 {
        return Ok(None);
    }
    if fs[5] != 1 {
        return Err(Error::Unsupported(
            "Unknown NCA patch metadata hash type".into(),
        ));
    }
    super::check_cancel(cancelled)?;
    let offset = BinaryReader::u64_le(&fs[0x1a0..]);
    let size = BinaryReader::u64_le(&fs[0x1a8..]);
    if size != 0xe8 {
        return Err(corrupt(
            0x1a8,
            "Invalid NCA patch metadata hash descriptor size",
        ));
    }
    let descriptor = source.read_at(offset, 0xe8)?.into_owned();
    if vnlens_crypto::hash::sha256::Sha256::digest(&descriptor).as_slice() != &fs[0x1b0..0x1d0] {
        return Err(corrupt(
            offset,
            "NCA patch metadata descriptor SHA-256 mismatch",
        ));
    }
    let info = &descriptor[8..];
    if &info[..4] != b"IVFC" || BinaryReader::u32_le(&info[4..]) != 0x20000 {
        return Err(corrupt(offset, "Invalid patch metadata IVFC header"));
    }
    let count = BinaryReader::u32_le(&info[12..]);
    let master_size = BinaryReader::u32_le(&info[8..]) as usize;
    if !(2..=7).contains(&count) || master_size == 0 || master_size > 32 {
        return Err(corrupt(offset, "Invalid patch metadata IVFC layout"));
    }
    let origin = BinaryReader::u64_le(&fs[0x100..]);
    let layer_info = BinaryReader::u64_le(&descriptor);
    if origin >= layer_info || layer_info >= offset {
        return Err(corrupt(offset, "Invalid patch metadata hash-layer range"));
    }
    let source = range(source, 0, offset)?;
    let mut hashes: Arc<dyn ReadAt> = Arc::new(Arc::<[u8]>::from(&info[0xc0..0xc0 + master_size]));
    for level in 0..count - 1 {
        let at = 16 + level as usize * 24;
        let location = if level == count - 2 {
            origin
        } else {
            add(layer_info, BinaryReader::u64_le(&info[at..]))?
        };
        let length = BinaryReader::u64_le(&info[at + 8..]);
        if level == count - 2 && add(location, length)? > layer_info {
            return Err(corrupt(
                location,
                "Patch metadata data overlaps hash layers",
            ));
        }
        let block = 1u64
            .checked_shl(BinaryReader::u32_le(&info[at + 16..]))
            .ok_or_else(|| corrupt(offset, "Invalid metadata IVFC block exponent"))?;
        hashes = super::nca::hash_level(source.clone(), hashes, location, length, block, true)?;
    }
    Ok(Some(Arc::new(Metadata {
        source: hashes,
        origin,
    })))
}
struct Metadata {
    source: Arc<dyn ReadAt>,
    origin: u64,
}
impl ReadAt for Metadata {
    fn len(&self) -> u64 {
        self.origin + self.source.len()
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        let at = offset
            .checked_sub(self.origin)
            .ok_or_else(|| BinaryIo::unexpected_eof("Read precedes patch metadata"))?;
        self.source.read_at(at, size)
    }
}
impl ReadAt for Indirect {
    fn len(&self) -> u64 {
        self.size
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        if offset > self.size || size as u64 > self.size - offset {
            return Err(BinaryIo::unexpected_eof("BKTR read exceeds mapping"));
        }
        if size == 0 {
            return Ok(Cow::Borrowed(&[]));
        }
        let mut index = self.mappings.partition_point(|m| m.virtual_at <= offset) - 1;
        let mut at = offset;
        let end = offset + size as u64;
        let mut output = Vec::with_capacity(size);
        while at < end {
            let mapping = &self.mappings[index];
            let stop = self
                .mappings
                .get(index + 1)
                .map_or(self.size, |next| next.virtual_at)
                .min(end);
            let length = usize::try_from(stop - at).map_err(io::Error::other)?;
            let bytes = self.sources[mapping.storage]
                .read_at(mapping.physical_at + at - mapping.virtual_at, length)?;
            if at == offset && stop == end {
                return Ok(bytes);
            }
            output.extend_from_slice(&bytes);
            at = stop;
            index += 1;
        }
        Ok(Cow::Owned(output))
    }
}

struct Counter {
    source: Arc<dyn ReadAt>,
    entries: Vec<(u64, bool, u32)>,
    size: u64,
    key: [u8; 16],
    upper: u64,
    absolute: u64,
    clear_prefix: u64,
}
pub(super) fn counter(
    raw: Arc<dyn ReadAt>,
    metadata: Arc<dyn ReadAt>,
    fs: &[u8],
    key: [u8; 16],
    absolute: u64,
    clear_prefix: u64,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<Arc<dyn ReadAt>> {
    let offset = BinaryReader::u64_le(&fs[0x120..]);
    let size = BinaryReader::u64_le(&fs[0x128..]);
    let table = table(
        range(metadata, offset, size)?.as_ref(),
        &fs[0x130..0x140],
        16,
        cancelled,
    )?;
    if table.end > offset {
        return Err(corrupt(offset, "BKTR counter entries exceed data region"));
    }
    let mut entries = Vec::new();
    for row in table.entries {
        let start = signed_offset(&row, offset)?;
        if !start.is_multiple_of(16) || row[8] > 1 {
            return Err(corrupt(offset, "Invalid BKTR counter entry"));
        }
        entries.push((
            start,
            row[8] == 0 && fs[4] != 1,
            BinaryReader::u32_le(&row[12..]),
        ));
    }
    if entries.first().is_some_and(|entry| entry.0 != 0) || !table.end.is_multiple_of(16) {
        return Err(corrupt(offset, "Invalid BKTR counter range"));
    }
    bounds(raw.as_ref(), 0, table.end)?;
    // Indirect-table metadata lies inside the counter-extended data region.
    Ok(Arc::new(Counter {
        source: raw,
        entries,
        size: table.end,
        key,
        upper: BinaryReader::u64_le(&fs[0x140..]),
        absolute,
        clear_prefix,
    }))
}
impl ReadAt for Counter {
    fn len(&self) -> u64 {
        self.size
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        if offset > self.size || size as u64 > self.size - offset {
            return Err(BinaryIo::unexpected_eof("BKTR counter read exceeds data"));
        }
        if size == 0 {
            return Ok(Cow::Borrowed(&[]));
        }
        let mut bytes = self.source.read_at(offset, size)?.into_owned();
        let mut at = offset;
        let end = offset + size as u64;
        while at < end {
            let index = self.entries.partition_point(|entry| entry.0 <= at) - 1;
            let (_, encrypted, generation) = self.entries[index];
            let stop = self
                .entries
                .get(index + 1)
                .map_or(self.size, |next| next.0)
                .min(end);
            let start = at.max(self.clear_prefix);
            if encrypted && start < stop {
                let upper = (self.upper & 0xffff_ffff_0000_0000) | u64::from(generation);
                let first = usize::try_from(start - offset).map_err(io::Error::other)?;
                let last = usize::try_from(stop - offset).map_err(io::Error::other)?;
                let position = self
                    .absolute
                    .checked_add(start)
                    .ok_or_else(|| BinaryIo::unexpected_eof("BKTR counter overflow"))?;
                apply_ctr128(&self.key, upper, position, &mut bytes[first..last]);
            }
            at = stop;
        }
        Ok(Cow::Owned(bytes))
    }
}

#[cfg(test)]
#[path = "../../tests/ns/patch.rs"]
mod tests;
