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

/// Read-only, randomly-accessible memory view of an archive file.
pub struct ArcView {
    path: PathBuf,
    map: Mmap,
}

impl std::fmt::Debug for ArcView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArcView")
            .field("path", &self.path)
            .field("len", &self.map.len())
            .finish()
    }
}

impl ArcView {
    /// Memory-maps the file at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        // SAFETY: read-only mapping; nvlens never mutates the backing file while
        // the view is alive. If an external process truncates the file, later
        // access faults via the OS (SIGBUS / error page), a known trade-off.
        let map = unsafe { Mmap::map(&file)? };
        Ok(Self { path, map })
    }

    /// Total size of the file in bytes.
    pub fn len(&self) -> u64 {
        self.map.len() as u64
    }

    /// Whether the file is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Source file name without directory; empty if it cannot be determined.
    pub fn file_name(&self) -> &str {
        self.path.file_name().and_then(|s| s.to_str()).unwrap_or("")
    }

    /// Full path of the source file.
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
        Ok(&self.map[offset as usize..end as usize])
    }

    /// Reads one byte at `offset`.
    pub fn read_u8(&self, offset: u64) -> Result<u8> {
        Ok(self.slice(offset, 1)?[0])
    }

    /// Reads a little-endian `u16` at `offset`.
    pub fn read_u16_le(&self, offset: u64) -> Result<u16> {
        Ok(BinaryReader::u16_le(self.slice(offset, 2)?))
    }

    /// Reads a little-endian `u32` at `offset`.
    pub fn read_u32_le(&self, offset: u64) -> Result<u32> {
        Ok(BinaryReader::u32_le(self.slice(offset, 4)?))
    }

    /// Reads a little-endian `i32` at `offset`.
    pub fn read_i32_le(&self, offset: u64) -> Result<i32> {
        Ok(BinaryReader::i32_le(self.slice(offset, 4)?))
    }
}
