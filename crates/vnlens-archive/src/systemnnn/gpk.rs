//! GTB: LE u32 count, count u32 name offsets, count u32 payload offsets,
//! then NUL-terminated CP932 names. Name offsets are relative to this pool.
//! NNNLib's GPK reader masks legacy offsets with 0x7fffffff. The over2G!
//! trailer instead selects count u64 offsets immediately before its 16 bytes.
use super::{Package, corrupt, name};
use std::sync::Arc;
use vnlens_core::{Archive, ArchiveFormat, ArchiveOptions, Entry, Format, ResourceKind, Result};
use vnlens_io::{ArcView, BinaryReader};

const SIGNATURES: &[u32] = &[0];
#[derive(Debug, Default)]
struct Gpk;
impl Format for Gpk {
    fn tag(&self) -> &'static str {
        "gpk/systemnnn"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["gpk"]
    }
    fn description(&self) -> &'static str {
        "SystemNNN GPK/GTB images"
    }
}
impl ArchiveFormat for Gpk {
    fn open(&self, view: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        let index = view.open_related(view.path().with_extension("gtb"))?;
        let data = index.slice(0, index.len())?;
        let mut r = BinaryReader::new(data);
        let count = r.read_u32_le()? as usize;
        let table_size = count
            .checked_mul(4)
            .ok_or_else(|| corrupt(0, "GTB table size overflow"))?;
        let mut names = BinaryReader::new(r.read_bytes(table_size)?);
        let mut offsets = BinaryReader::new(r.read_bytes(table_size)?);
        let name_base = r.position();
        let (name_end, mut wide) = if data.ends_with(b"\0\0\0\0\0\0\0\0over2G!\0") {
            let trailer_size = table_size
                .checked_mul(2)
                .and_then(|size| size.checked_add(16))
                .ok_or_else(|| corrupt(0, "GTB extended table size overflow"))?;
            let start = data
                .len()
                .checked_sub(trailer_size)
                .filter(|&start| start >= name_base)
                .ok_or_else(|| corrupt(0, "GTB extended offset table overlaps index"))?;
            (
                start,
                Some(BinaryReader::new(&data[start..data.len() - 16])),
            )
        } else {
            (data.len(), None)
        };
        let pool = &data[name_base..name_end];
        let mut entries: Vec<Entry> = Vec::new();
        for _ in 0..count {
            let n = names.read_u32_le()? as usize;
            let mut text = BinaryReader::new_at(pool, n)?;
            let start = text.position();
            while text.read_u8()? != 0 {}
            let entry_name = name(&pool[start..text.position() - 1])? + ".dwq";
            let legacy = u64::from(offsets.read_u32_le()? & 0x7fff_ffff);
            let offset = if let Some(wide) = wide.as_mut() {
                wide.read_u64_le()?
            } else {
                legacy
            };
            if offset > view.len() {
                return Err(corrupt(offset, "GPK entry exceeds data file"));
            }
            if let Some(previous) = entries.last_mut() {
                previous.size = offset
                    .checked_sub(previous.offset)
                    .ok_or_else(|| corrupt(offset, "GPK offsets are not ordered"))?;
            }
            entries.push(Entry {
                name: entry_name,
                kind: ResourceKind::Image,
                offset,
                size: view.len() - offset,
                packed: None,
            });
        }
        Ok(Box::new(Package {
            view: view.clone(),
            entries,
        }))
    }
}
vnlens_core::register_archive!(Gpk);
