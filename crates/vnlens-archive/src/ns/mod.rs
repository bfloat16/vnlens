//! Nintendo Switch archives. Layouts follow LibHac XciHeader,
//! PartitionFileSystemCore, NcaHeader/NcaFsHeader and HierarchicalRomFileTable.
//! Integer fields are little-endian; AES counters/tweaks use Nintendo's byte
//! order. Mounting consumes metadata only; sources retain lazy payload access.
mod compression;
mod integrity;
mod keys;
mod nca;
mod package;
mod partition;
mod patch;
mod romfs;

#[cfg(test)]
#[path = "../../tests/ns/fixtures.rs"]
mod fixtures;

use keys::Keys;
use nca::Nca;
use partition::{open_partition, open_xci};
use romfs::open_romfs;

use std::{borrow::Cow, sync::Arc};
use vnlens_core::{Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, Result};
use vnlens_io::{ArcView, BinaryIo, RangeSource, ReadAt};

/// Associates physical NS package selections with their base application.
/// Only sibling package indices, NCA headers, tickets and CNMT metadata are
/// read. Missing keys, corrupt metadata and cancellation remain errors.
pub fn application_paths(
    directory: &std::path::Path,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<std::collections::BTreeMap<std::path::PathBuf, std::path::PathBuf>> {
    package::Catalog::load(directory, cancelled)?.application_paths(cancelled)
}

/// An indexed filesystem. Entries retain original names and storage ranges.
pub struct FileSystem {
    pub entries: Vec<Entry>,
    source: Arc<dyn ReadAt>,
    hashes: Vec<Option<integrity::RegionHash>>,
}

impl std::fmt::Debug for FileSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSystem")
            .field("entries", &self.entries)
            .finish_non_exhaustive()
    }
}

impl FileSystem {
    fn entry_hash(&self, entry: &Entry) -> Result<Option<&integrity::RegionHash>> {
        if self.hashes.is_empty() {
            return Ok(None);
        }
        let index = self
            .entries
            .iter()
            .position(|stored| {
                stored.offset == entry.offset
                    && stored.size == entry.size
                    && stored.name == entry.name
            })
            .ok_or_else(|| corrupt(entry.offset, "Entry does not belong to this NS filesystem"))?;
        Ok(self.hashes.get(index).and_then(Option::as_ref))
    }

    /// Returns the requested file without materializing its body.
    pub fn source(&self, entry: &Entry) -> Result<Arc<dyn ReadAt>> {
        let hash = self.entry_hash(entry)?.cloned();
        let source = range(self.source.clone(), entry.offset, entry.size)?;
        match hash {
            Some(hash) => Ok(Arc::new(integrity::HashedRegion::new(source, hash))),
            None => Ok(source),
        }
    }

    pub fn read(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let size = memory(entry.size)?;
        if let Some(hash) = self.entry_hash(entry)? {
            let offset = add(entry.offset, hash.offset)?;
            let actual = integrity::hash_range(self.source.as_ref(), offset, hash.size, hash.size)?;
            if actual != hash.expected {
                return Err(corrupt(offset, "HFS0 SHA-256 mismatch"));
            }
        }
        Ok(self.source.read_at(entry.offset, size)?)
    }
}

fn range(source: Arc<dyn ReadAt>, offset: u64, size: u64) -> Result<Arc<dyn ReadAt>> {
    Ok(Arc::new(RangeSource::new(source, offset, size)?))
}

fn add(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| corrupt(left, "NS offset overflow"))
}

fn memory(size: u64) -> Result<usize> {
    usize::try_from(size)
        .map_err(|_| Error::Unsupported("NS range cannot fit in address space".into()))
}

fn corrupt(offset: u64, reason: impl Into<String>) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

fn name(bytes: &[u8], offset: u64) -> Result<String> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| corrupt(offset, "Invalid UTF-8 NS filename"))
}

fn bounds(source: &dyn ReadAt, offset: u64, size: u64) -> Result<()> {
    if offset > source.len() || size > source.len() - offset {
        return Err(BinaryIo::unexpected_eof("NS range exceeds source").into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/ns/filesystem.rs"]
mod filesystem_tests;

macro_rules! filesystem_format {
    ($type:ident, $tag:literal, $signatures:expr, $extensions:expr, $description:literal, $open:expr) => {
        #[derive(Debug, Default)]
        struct $type;
        impl Format for $type {
            fn tag(&self) -> &'static str {
                $tag
            }
            fn signatures(&self) -> &'static [u32] {
                $signatures
            }
            fn extensions(&self) -> &'static [&'static str] {
                $extensions
            }
            fn description(&self) -> &'static str {
                $description
            }
        }
        impl ArchiveFormat for $type {
            fn open(&self, view: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
                Ok(Box::new(($open)(view.clone())?))
            }
            fn open_source(
                &self,
                source: Arc<dyn ReadAt>,
                _: &str,
                _: &ArchiveOptions,
            ) -> Result<Option<Box<dyn Archive>>> {
                Ok(Some(Box::new(($open)(source)?)))
            }
        }
        vnlens_core::register_archive!($type);
    };
}

filesystem_format!(
    Xci,
    "ns/xci",
    &[0],
    &["xci"],
    "Nintendo Switch game card image",
    open_xci
);
filesystem_format!(
    Pfs,
    "ns/pfs0",
    &[0x30534650],
    &["nsp", "pfs0"],
    "Nintendo Switch partition filesystem",
    |source| open_partition(source, false)
);
filesystem_format!(
    Hfs,
    "ns/hfs0",
    &[0x30534648],
    &["hfs0"],
    "Nintendo Switch hashed partition filesystem",
    |source| open_partition(source, true)
);
filesystem_format!(
    Rom,
    "ns/romfs",
    &[0x00000050],
    &["romfs"],
    "Nintendo Switch read-only filesystem",
    open_romfs
);
#[derive(Debug, Default)]
struct Content;
impl Format for Content {
    fn tag(&self) -> &'static str {
        "ns/nca"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["nca"]
    }
    fn description(&self) -> &'static str {
        "Nintendo Switch content archive"
    }
}
impl ArchiveFormat for Content {
    fn open(&self, view: &Arc<ArcView>, options: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        Ok(Box::new(
            Nca::open(view.clone())?.with_context(&view.path().to_string_lossy(), options),
        ))
    }
    fn open_source(
        &self,
        source: Arc<dyn ReadAt>,
        name: &str,
        options: &ArchiveOptions,
    ) -> Result<Option<Box<dyn Archive>>> {
        Ok(Some(Box::new(
            Nca::open(source)?.with_context(name, options),
        )))
    }
}
vnlens_core::register_archive!(Content);

impl Archive for FileSystem {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        self.read(entry)
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn ReadAt>>> {
        self.source(entry).map(Some)
    }
}

impl Archive for Nca {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let source = self.source(entry, &std::sync::atomic::AtomicBool::new(false))?;
        let size = usize::try_from(source.len()).map_err(|_| {
            vnlens_core::Error::Unsupported(
                "NCA filesystem cannot fit in address space; use its streaming source".into(),
            )
        })?;
        Ok(Cow::Owned(source.read_at(0, size)?.into_owned()))
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn ReadAt>>> {
        self.source(entry, &std::sync::atomic::AtomicBool::new(false))
            .map(Some)
    }
    fn open_entry_source_cancellable(
        &self,
        entry: &Entry,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<Option<Arc<dyn ReadAt>>> {
        self.source(entry, cancelled).map(Some)
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        self.read_raw(entry)
    }
}

#[cfg(test)]
#[path = "../../tests/ns/mod.rs"]
mod tests;

pub(super) fn check_cancel(cancelled: &std::sync::atomic::AtomicBool) -> Result<()> {
    if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
