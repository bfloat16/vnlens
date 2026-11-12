//! SEEN.TXT: the native LoadPackHeader reads 10,000 LE (offset,size) pairs.
//! IDs are the index positions, including holes. Each stored resource retains
//! its own compiler header and encoding. The script reader decrypts/decodes
//! the selected resource for disassembly; archive extraction preserves its file.
use std::{borrow::Cow, sync::Arc};
use vnlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, ResourceKind, Result,
};
use vnlens_io::{ArcView, BinaryReader};

#[derive(Debug, Default)]
struct Seen;
impl Format for Seen {
    fn tag(&self) -> &'static str {
        "seen/reallive"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["txt"]
    }
    fn description(&self) -> &'static str {
        "RealLive SEEN script archive"
    }
}
struct SeenArchive {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
}
impl ArchiveFormat for Seen {
    fn open(&self, view: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        let mut r = BinaryReader::new(view.slice(0, 80000)?);
        let mut entries = Vec::new();
        for id in 0..10000 {
            let offset = u64::from(r.read_u32_le()?);
            let size = u64::from(r.read_u32_le()?);
            if offset == 0 && size == 0 {
                continue;
            }
            let entry = Entry {
                name: format!("Seen{id:04}.txt"),
                kind: ResourceKind::Script,
                offset,
                size,
                packed: None,
            };
            if offset < 80000 {
                return Err(Error::Corrupt {
                    offset,
                    reason: "RealLive SEEN entry overlaps the index".into(),
                });
            }
            if !entry.check_placement(view.len()) {
                return Err(vnlens_io::BinaryIo::unexpected_eof(
                    "RealLive SEEN entry exceeds archive storage",
                )
                .into());
            }
            entries.push(entry);
        }
        Ok(Box::new(SeenArchive {
            view: view.clone(),
            entries,
        }))
    }
}
impl Archive for SeenArchive {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        if !self
            .entries
            .iter()
            .any(|e| e.name == entry.name && e.offset == entry.offset && e.size == entry.size)
        {
            return Err(Error::Corrupt {
                offset: entry.offset,
                reason: "Entry does not belong to this SEEN archive".into(),
            });
        }
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
}
vnlens_core::register_archive!(Seen);

#[cfg(test)]
#[path = "../../tests/reallive/mod.rs"]
mod tests;
