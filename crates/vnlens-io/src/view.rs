//! Memory-mapped read-only view of an archive file.
//!
//! Provides bounds-checked random access. All integer decoding is delegated to
//! [`BinaryReader`], keeping [`crate::binary`] the single source of binary I/O.
//! Out-of-range access returns [`std::io::Error`] (`UnexpectedEof`), never panics.

use std::fs::File;
use std::io::Result;
use std::path::{Path, PathBuf};

use memmap2::Mmap;

use crate::binary::{BinaryIo, BinaryReader};
use std::sync::Arc;

/// Read-only, randomly-accessible memory view of an archive file.
pub struct ArcView {
    path: PathBuf,
    map: Option<Mmap>,
    bytes: Option<Arc<[u8]>>,
    files: Option<Arc<crate::FileSystem>>,
}

impl std::fmt::Debug for ArcView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArcView")
            .field("path", &self.path)
            .field("len", &self.len())
            .finish()
    }
}

impl ArcView {
    /// Memory-maps the file at `path`.
    #[allow(unsafe_code)]
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        let map = if file.metadata()?.len() == 0 {
            None
        } else {
            // SAFETY: vnlens never modifies a mapped source. Callers must keep
            // external writers from truncating or changing it during use.
            Some(unsafe { Mmap::map(&file)? })
        };
        Ok(Self {
            path,
            map,
            bytes: None,
            files: None,
        })
    }

    /// Creates a named immutable view for an embedded file; no disk output.
    #[must_use]
    pub fn from_bytes(path: PathBuf, bytes: Arc<[u8]>) -> Self {
        Self {
            path,
            map: None,
            bytes: Some(bytes),
            files: None,
        }
    }

    pub(crate) fn with_files(mut self, files: Arc<crate::FileSystem>) -> Self {
        self.files = Some(files);
        self
    }

    /// Opens a companion through the same game directory overlay as this view.
    pub fn open_related(&self, path: impl AsRef<Path>) -> Result<Self> {
        match &self.files {
            Some(files) => files.open(path.as_ref()),
            None => Self::open(path),
        }
    }

    /// Checks companion metadata without reading its contents.
    pub fn related_len(&self, path: &Path) -> Result<u64> {
        match &self.files {
            Some(files) => files.metadata(path).map(|m| m.len),
            None => std::fs::metadata(path).map(|m| m.len()),
        }
    }

    /// Total size of the file in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.bytes.as_ref().map_or_else(
            || self.map.as_ref().map_or(0, |map| map.len() as u64),
            |bytes| bytes.len() as u64,
        )
    }

    /// Whether the file is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Source file name without directory; empty if it cannot be determined.
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.path.file_name().and_then(|s| s.to_str()).unwrap_or("")
    }

    /// Full path of the source file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Borrows the range `[offset, offset + size)`; errors if out of range.
    pub fn slice(&self, offset: u64, size: u64) -> Result<&[u8]> {
        let end = offset
            .checked_add(size)
            .filter(|&end| end <= self.len())
            .ok_or_else(|| {
                BinaryIo::unexpected_eof(format!(
                    "out of bounds: off=0x{offset:X} size={size} len=0x{:X}",
                    self.len()
                ))
            })?;
        let start = usize::try_from(offset)
            .map_err(|_| BinaryIo::unexpected_eof("slice offset does not fit usize"))?;
        let stop = usize::try_from(end)
            .map_err(|_| BinaryIo::unexpected_eof("slice end does not fit usize"))?;
        let bytes = self.bytes.as_deref().or(self.map.as_deref()).unwrap_or(&[]);
        Ok(&bytes[start..stop])
    }

    /// Reads a little-endian `u32` at `offset`.
    pub fn read_u32_le(&self, offset: u64) -> Result<u32> {
        Ok(BinaryReader::u32_le(self.slice(offset, 4)?))
    }
}
