//! MAGES MPK v2: 0x40-byte header and 0x100-byte little-endian index records.
//! Records contain flags, resource ID, three u64 storage/size fields and a
//! NUL-terminated UTF-8 name occupying the remainder of the record. Stored
//! entries have flags=0 and equal stored/logical sizes. Empty index slots are
//! retained in the source table but do not name resources. Payloads remain lazy.
use std::{borrow::Cow, sync::Arc};
use vnlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, ResourceKind, Result,
};
use vnlens_io::{ArcView, BinaryReader, RangeSource, ReadAt};

#[derive(Debug, Default)]
struct Mpk;

impl Format for Mpk {
    fn tag(&self) -> &'static str {
        "mpk/mages"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x004b_504d]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["mpk"]
    }
    fn description(&self) -> &'static str {
        "MAGES MPK resource archive"
    }
}

impl ArchiveFormat for Mpk {
    fn open(&self, view: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        let mut header = BinaryReader::new(view.slice(0, 0x40)?);
        if header.read_bytes(4)? != b"MPK\0" {
            return Err(corrupt(0, "Invalid MPK signature"));
        }
        let version = header.read_u32_le()?;
        if version != 0x20000 {
            return Err(Error::Unsupported(format!("MPK version 0x{version:X}")));
        }
        let count = header.read_u32_le()?;
        let index_end = 0x40 + u64::from(count) * 0x100;
        let mut table = BinaryReader::new(view.slice(0x40, u64::from(count) * 0x100)?);
        let mut entries = Vec::new();
        for _ in 0..count {
            let at = 0x40 + table.position() as u64;
            let flags = table.read_u32_le()?;
            let _id = table.read_u32_le()?;
            let offset = table.read_u64_le()?;
            let size = table.read_u64_le()?;
            let logical = table.read_u64_le()?;
            let raw = table.read_bytes(0xe0)?;
            let end = raw
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| corrupt(at + 0x20, "Unterminated MPK name"))?;
            if end == 0 && offset == 0 && size == 0 && logical == 0 {
                continue;
            }
            let name = std::str::from_utf8(&raw[..end])
                .map_err(|_| corrupt(at + 0x20, "Invalid MPK UTF-8 name"))?
                .to_owned();
            if flags != 0 || size != logical {
                return Err(Error::Unsupported(format!(
                    "MPK storage flags 0x{flags:X}, stored size {size}, logical size {logical}"
                )));
            }
            let entry = Entry {
                name,
                kind: ResourceKind::Unknown,
                offset,
                size,
                packed: None,
            };
            if !entry.check_placement(view.len()) {
                return Err(corrupt(at + 8, "MPK entry exceeds archive storage"));
            }
            if size != 0 && offset < index_end {
                return Err(corrupt(at + 8, "MPK entry overlaps index"));
            }
            entries.push(entry);
        }
        Ok(Box::new(Pack {
            view: view.clone(),
            entries,
        }))
    }
}

#[derive(Debug)]
struct Pack {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
}

impl Archive for Pack {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn ReadAt>>> {
        Ok(Some(Arc::new(RangeSource::new(
            self.view.clone(),
            entry.offset,
            entry.size,
        )?)))
    }
}

fn corrupt(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

vnlens_core::register_archive!(Mpk);

#[cfg(test)]
#[path = "../../tests/mages/mod.rs"]
mod tests;
