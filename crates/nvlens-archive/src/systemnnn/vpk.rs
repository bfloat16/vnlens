//! VTB consists of 12-byte records: eight CP932 name bytes (optional NUL)
//! and an LE u32 offset. The last record is a sentinel, not a resource.
use super::{Package, corrupt, name};
use nvlens_core::{Archive, ArchiveFormat, ArchiveOptions, Entry, Format, ResourceKind, Result};
use nvlens_io::{ArcView, BinaryReader};
use std::sync::Arc;

const SIGNATURES: &[u32] = &[0];
#[derive(Debug, Default)]
struct Vpk;
impl Format for Vpk {
    fn tag(&self) -> &'static str {
        "vpk/systemnnn"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["vpk"]
    }
    fn description(&self) -> &'static str {
        "SystemNNN VPK/VTB voices"
    }
}
impl ArchiveFormat for Vpk {
    fn open(&self, view: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        let index = ArcView::open(view.path().with_extension("vtb"))?;
        let mut r = BinaryReader::new(index.slice(0, index.len())?);
        if !r.remaining().is_multiple_of(12) {
            return Err(corrupt(0, "VTB contains an incomplete record"));
        }
        let mut current_name = r.read_bytes(8)?;
        let mut offset = u64::from(r.read_u32_le()?);
        let mut entries = Vec::new();
        while r.remaining() != 0 {
            let next_name = r.read_bytes(8)?;
            let next = u64::from(r.read_u32_le()?);
            let size = next
                .checked_sub(offset)
                .ok_or_else(|| corrupt(offset, "VPK offsets are not ordered"))?;
            if next > view.len() {
                return Err(corrupt(next, "VPK entry exceeds data file"));
            }
            entries.push(Entry {
                name: name(current_name)? + ".vaw",
                kind: ResourceKind::Audio,
                offset,
                size,
                packed: None,
            });
            current_name = next_name;
            offset = next;
        }
        if offset > view.len() {
            return Err(corrupt(offset, "VTB terminal offset exceeds data file"));
        }
        Ok(Box::new(Package {
            view: view.clone(),
            entries,
        }))
    }
}
nvlens_core::register_archive!(Vpk);
