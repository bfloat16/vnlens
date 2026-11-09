//! ExHIBIT AiFS: resHH00.grp indexes resHHNN.grp data volumes (hex numbers).
//! UxArchiveIdFile::load reads a 16-byte LE header and variable versioned
//! tables: volume, first ID, last ID, count, then (offset, size) u32 pairs.
//! Payload volumes are mapped only when an entry is requested.

use nvlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, ResourceKind, Result,
};
use nvlens_io::{ArcView, BinaryReader};
use std::{
    borrow::Cow,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

const SIGNATURES: &[u32] = &[0x5346_6941, 0];

#[derive(Debug, Default)]
struct Grp;
impl Format for Grp {
    fn tag(&self) -> &'static str {
        "grp/exhibit"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["grp"]
    }
    fn description(&self) -> &'static str {
        "ExHIBIT AiFS resource group"
    }
}
struct Volume {
    path: PathBuf,
    opened: OnceLock<std::io::Result<Arc<ArcView>>>,
}
struct Group {
    entries: Vec<Entry>,
    sources: Vec<usize>,
    volumes: Vec<Volume>,
}
impl ArchiveFormat for Grp {
    fn open(&self, view: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        let stem = view
            .path()
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        let digits = stem
            .get(3..)
            .filter(|_| stem.get(..3).is_some_and(|s| s.eq_ignore_ascii_case("res")))
            .ok_or_else(|| {
                Error::Unsupported("ExHIBIT GRP requires its resHHNN filename".into())
            })?;
        let number = u32::from_str_radix(digits, 16)
            .map_err(|_| Error::Unsupported("Invalid ExHIBIT volume number".into()))?;
        let base = number & !255;
        let selected = number & 255;
        let index = if selected == 0 {
            view.clone()
        } else {
            Arc::new(ArcView::open(
                view.path().with_file_name(format!("res{base:04x}.grp")),
            )?)
        };
        let mut r = BinaryReader::new(index.slice(0, index.len())?);
        if r.read_u32_le()? != 0x5346_6941 {
            return Err(Error::InvalidFormat);
        }
        let _version = r.read_u32_le()?;
        let group = r.read_u32_le()?;
        if group != number >> 8 {
            return Err(corrupt(8, "AiFS group differs from filename"));
        }
        let tables = r.read_u32_le()?;
        let mut result = Group {
            entries: Vec::new(),
            sources: Vec::new(),
            volumes: Vec::new(),
        };
        for _ in 0..tables {
            let mut volume = r.read_u32_le()?;
            let version = (volume >> 24) & 127;
            if version != 0 && version != 127 {
                volume = r.read_u32_le()?;
            }
            let first = r.read_u32_le()?;
            let _last = r.read_u32_le()?;
            let count = r.read_u32_le()?;
            let bytes = usize::try_from(u64::from(count) * 8)
                .map_err(|_| corrupt(r.position(), "AiFS table exceeds address space"))?;
            let mut table = BinaryReader::new(r.read_bytes(bytes)?);
            if selected != 0 && volume != selected {
                continue;
            }
            let source = result.volumes.len();
            let path = index
                .path()
                .with_file_name(format!("res{:02x}{volume:02x}.grp", number >> 8));
            let opened = OnceLock::new();
            if selected != 0 && selected == volume {
                let _ = opened.set(Ok(view.clone()));
            }
            result.volumes.push(Volume { path, opened });
            for i in 0..count {
                let offset = u64::from(table.read_u32_le()?);
                let size = u64::from(table.read_u32_le()?);
                if size == 0 {
                    continue;
                }
                let id = first
                    .checked_add(i)
                    .ok_or_else(|| corrupt(r.position(), "AiFS resource ID overflow"))?;
                result.entries.push(Entry {
                    name: format!("{id:05}"),
                    kind: ResourceKind::Unknown,
                    offset,
                    size,
                    packed: None,
                });
                result.sources.push(source);
            }
        }
        if selected != 0 && result.volumes.is_empty() {
            return Err(corrupt(16, "AiFS volume is not indexed"));
        }
        Ok(Box::new(result))
    }
}
impl Archive for Group {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(
            self.entry_view(entry)?.slice(entry.offset, entry.size)?,
        ))
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn nvlens_io::ReadAt>>> {
        Ok(Some(Arc::new(nvlens_io::RangeSource::new(
            self.entry_view(entry)?.clone(),
            entry.offset,
            entry.size,
        )?)))
    }
}
impl Group {
    // Share the lazily opened volume between extraction and independent
    // playback cursors; neither path copies the entire encoded resource.
    fn entry_view(&self, entry: &Entry) -> Result<&Arc<ArcView>> {
        let i = self
            .entries
            .iter()
            .position(|e| e.name == entry.name && e.offset == entry.offset && e.size == entry.size)
            .ok_or(Error::InvalidFormat)?;
        let volume = &self.volumes[self.sources[i]];
        let mapped = volume
            .opened
            .get_or_init(|| ArcView::open(&volume.path).map(Arc::new));
        Ok(mapped.as_ref().map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("Opening AiFS volume {}: {e}", volume.path.display()),
            )
        })?)
    }
}
fn corrupt(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
nvlens_core::register_archive!(Grp);

#[cfg(test)]
#[path = "../../tests/exhibit/mod.rs"]
mod tests;
