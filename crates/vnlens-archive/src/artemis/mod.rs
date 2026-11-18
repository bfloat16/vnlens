//! Artemis PF8 packages. CPackFile::read (sub_140188180) repeats the directory
//! SHA-1 digest from byte zero of each resource, including on seek. Numbered
//! companions are independent packages: later .000..999 definitions override
//! earlier ones (sub_1401884A0). Mounting reads only each package's directory.
mod read;

use std::{borrow::Cow, collections::BTreeMap, fmt, path::PathBuf, sync::Arc};
use vnlens_core::{Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, Result, Secret};
use vnlens_crypto::cipher::xor;
use vnlens_io::{ArcView, RangeSource, ReadAt};

const SIGNATURES: &[u32] = &[0]; // The fixed marker is three bytes, not a u32.

#[derive(Debug, Default)]
struct Pfs;
impl Format for Pfs {
    fn tag(&self) -> &'static str {
        "pfs/artemis"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["pfs"]
    }
    fn description(&self) -> &'static str {
        "Artemis PF8 resource archive"
    }
}
impl ArchiveFormat for Pfs {
    fn open(&self, view: &Arc<ArcView>, options: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        if options.numbers.get("artemis_companions") != Some(&1) {
            return Ok(Box::new(Package::new(view.clone())?));
        }
        let mut base = view.clone();
        let mut path = view.path().to_path_buf();
        if path.extension().is_some_and(|ext| {
            let ext = ext.to_string_lossy();
            ext.len() == 3 && ext.bytes().all(|b| b.is_ascii_digit())
        }) {
            let candidate = path.with_extension("");
            if candidate
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("pfs"))
                && exists(view, &candidate)?
            {
                base = Arc::new(view.open_related(&candidate)?);
                path = candidate;
            }
        }
        let mut package = Package::new(base.clone())?;
        if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("pfs"))
        {
            // Three decimal digits are the native companion naming field.
            for part in 0..1000 {
                let mut name = path.as_os_str().to_os_string();
                name.push(format!(".{part:03}"));
                let name = PathBuf::from(name);
                if exists(&base, &name)? {
                    package.append(Arc::new(base.open_related(&name)?))?;
                }
            }
        }
        Ok(Box::new(package))
    }
    fn open_source(
        &self,
        source: Arc<dyn ReadAt>,
        _: &str,
        options: &ArchiveOptions,
    ) -> Result<Option<Box<dyn Archive>>> {
        // Physical sets need the view's existing game filesystem to open their
        // companions. Nested, independent PFS files retain a streaming source.
        if options.numbers.get("artemis_companions") == Some(&1) {
            return Ok(None);
        }
        Ok(Some(Box::new(Package::new(source)?)))
    }
}
vnlens_core::register_archive!(Pfs);

fn exists(view: &ArcView, path: &std::path::Path) -> Result<bool> {
    match view.related_len(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

struct Part {
    source: Arc<dyn ReadAt>,
    key: Secret,
}
struct Package {
    parts: Vec<Part>,
    entries: Vec<Entry>,
    locations: Vec<usize>,
    names: BTreeMap<String, usize>,
}
impl fmt::Debug for Package {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArtemisPfs")
            .field("parts", &self.parts.len())
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}
impl Package {
    fn new(source: Arc<dyn ReadAt>) -> Result<Self> {
        let mut package = Self {
            parts: Vec::new(),
            entries: Vec::new(),
            locations: Vec::new(),
            names: BTreeMap::new(),
        };
        package.append(source)?;
        Ok(package)
    }
    fn append(&mut self, source: Arc<dyn ReadAt>) -> Result<()> {
        let (entries, key) = read::index(source.as_ref())?;
        let part = self.parts.len();
        self.parts.push(Part { source, key });
        for entry in entries {
            let name = entry.name.replace('/', "\\");
            if let Some(&index) = self.names.get(&name) {
                self.entries[index] = entry;
                self.locations[index] = part;
            } else {
                self.names.insert(name, self.entries.len());
                self.entries.push(entry);
                self.locations.push(part);
            }
        }
        Ok(())
    }
    fn part(&self, entry: &Entry) -> Result<&Part> {
        let index = self
            .names
            .get(&entry.name.replace('/', "\\"))
            .copied()
            .ok_or_else(|| bad(entry.offset, "Entry does not belong to this PFS"))?;
        let stored = &self.entries[index];
        if stored.name != entry.name || stored.offset != entry.offset || stored.size != entry.size {
            return Err(bad(entry.offset, "Entry does not belong to this PFS"));
        }
        Ok(&self.parts[self.locations[index]])
    }
}
impl Archive for Package {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let part = self.part(entry)?;
        Ok(part.source.read_at(
            entry.offset,
            usize::try_from(entry.size)
                .map_err(|_| bad(entry.offset, "PFS resource exceeds address space"))?,
        )?)
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let key = &self.part(entry)?.key;
        let mut data = self.open_entry_raw(entry)?.into_owned();
        xor::apply(&mut data, key.bytes()).map_err(|e| bad(entry.offset, &e.to_string()))?;
        Ok(Cow::Owned(data))
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn ReadAt>>> {
        let part = self.part(entry)?;
        Ok(Some(Arc::new(EntrySource {
            source: RangeSource::new(part.source.clone(), entry.offset, entry.size)?,
            key: part.key.clone(),
        })))
    }
}

#[derive(Debug)]
struct EntrySource {
    source: RangeSource,
    key: Secret,
}
impl ReadAt for EntrySource {
    fn len(&self) -> u64 {
        self.source.len()
    }
    fn read_at(&self, offset: u64, size: usize) -> std::io::Result<Cow<'_, [u8]>> {
        let mut data = self.source.read_at(offset, size)?.into_owned();
        xor::apply_at(&mut data, self.key.bytes(), offset).map_err(std::io::Error::other)?;
        Ok(Cow::Owned(data))
    }
}

fn bad(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "../../tests/artemis/mod.rs"]
mod tests;
