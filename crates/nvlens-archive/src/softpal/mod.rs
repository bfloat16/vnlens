//! PAL PAC: 12-byte header, 255 first-byte lookup buckets (8 bytes each),
//! then count records of CP932 name[32], LE size and absolute offset.
//! Verified against PalFileCreateEx / sub_100A9AD0. Payloads are lazy.
use nvlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, ResourceKind, Result,
};
use nvlens_io::{ArcView, BinaryReader, RangeSource, ReadAt};
use std::{borrow::Cow, sync::Arc};
const SIGNATURES: &[u32] = &[0x2043_4150];
#[derive(Debug, Default)]
struct Pac;
impl Format for Pac {
    fn tag(&self) -> &'static str {
        "pac/softpal"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["pac"]
    }
    fn description(&self) -> &'static str {
        "Softpal PAC resources"
    }
}
impl ArchiveFormat for Pac {
    fn open(&self, view: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        Ok(Box::new(Package {
            view: view.clone(),
            entries: index(view.as_ref())?,
        }))
    }
}
fn index(source: &dyn ReadAt) -> Result<Vec<Entry>> {
    let header = source.read_at(0, 12)?;
    let mut r = BinaryReader::new(&header);
    if r.read_bytes(4)? != b"PAC " {
        return Err(Error::InvalidFormat);
    }
    r.read_u32_le()?;
    let count = u64::from(r.read_u32_le()?);
    let bytes = source.read_at(
        0x804,
        usize::try_from(count * 40)
            .map_err(|_| Error::Unsupported("PAC index exceeds address space".into()))?,
    )?;
    let mut r = BinaryReader::new(&bytes);
    let mut entries = Vec::new();
    for _ in 0..count {
        let field = r.read_bytes(32)?;
        let field = field.split(|b| *b == 0).next().unwrap_or_default();
        let (name, _, errors) = encoding_rs::SHIFT_JIS.decode(field);
        if errors {
            return Err(Error::Corrupt {
                offset: 0x804 + r.position() as u64 - 32,
                reason: "Invalid PAC CP932 name".into(),
            });
        }
        let size = u64::from(r.read_u32_le()?);
        let offset = u64::from(r.read_u32_le()?);
        let entry = Entry {
            name: name.into_owned(),
            offset,
            size,
            packed: None,
            kind: ResourceKind::Unknown,
        };
        if offset < 0x804 + count * 40 || !entry.check_placement(source.len()) {
            return Err(Error::Corrupt {
                offset,
                reason: "PAC entry is outside its payload region".into(),
            });
        }
        entries.push(entry);
    }
    Ok(entries)
}
#[derive(Debug)]
struct Package {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
}
impl Archive for Package {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        nvlens_script::softpal::decode_envelope(self.view.slice(entry.offset, entry.size)?)
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn ReadAt>>> {
        if self.view.slice(entry.offset, entry.size.min(1))? == b"$" {
            return Ok(None);
        }
        Ok(Some(Arc::new(RangeSource::new(
            self.view.clone(),
            entry.offset,
            entry.size,
        )?)))
    }
}
nvlens_core::register_archive!(Pac);
#[cfg(test)]
#[path = "../../tests/softpal/mod.rs"]
mod tests;
