//! Independent cursors over mapped or transformed random-access sources.
#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::io;

use crate::{ArcView, BinaryIo, BinaryReader};

/// A byte source whose ranges can be requested without materializing its body.
pub trait ReadAt: Send + Sync {
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>>;
}

impl ReadAt for ArcView {
    fn len(&self) -> u64 {
        self.len()
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        self.slice(offset, size as u64).map(Cow::Borrowed)
    }
}

impl ReadAt for &[u8] {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        let start = usize::try_from(offset)
            .map_err(|_| BinaryIo::unexpected_eof("source offset does not fit usize"))?;
        let end = start
            .checked_add(size)
            .ok_or_else(|| BinaryIo::unexpected_eof("source range overflow"))?;
        self.get(start..end)
            .map(Cow::Borrowed)
            .ok_or_else(|| BinaryIo::unexpected_eof("source range exceeds data"))
    }
}

/// A cursor that requests only the bytes consumed by the parser.
pub struct BinarySourceReader<'a> {
    source: &'a dyn ReadAt,
    position: usize,
}

impl std::fmt::Debug for BinarySourceReader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinarySourceReader")
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

impl<'a> BinarySourceReader<'a> {
    #[must_use]
    pub fn new(source: &'a dyn ReadAt) -> Self {
        Self {
            source,
            position: 0,
        }
    }

    pub fn new_at(source: &'a dyn ReadAt, position: usize) -> io::Result<Self> {
        if position as u64 > source.len() {
            return Err(BinaryIo::unexpected_eof("cursor exceeds source"));
        }
        Ok(Self { source, position })
    }

    #[must_use]
    pub fn position(&self) -> usize {
        self.position
    }

    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.source.len().saturating_sub(self.position as u64)
    }

    pub fn read_bytes(&mut self, size: usize) -> io::Result<Cow<'a, [u8]>> {
        let end = self
            .position
            .checked_add(size)
            .ok_or_else(|| BinaryIo::unexpected_eof("cursor overflow"))?;
        let bytes = self.source.read_at(self.position as u64, size)?;
        if bytes.len() != size {
            return Err(BinaryIo::unexpected_eof("source returned a short range"));
        }
        self.position = end;
        Ok(bytes)
    }

    pub fn read_u8(&mut self) -> io::Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }
    pub fn read_u16_le(&mut self) -> io::Result<u16> {
        Ok(BinaryReader::u16_le(&self.read_bytes(2)?))
    }
    pub fn read_u32_le(&mut self) -> io::Result<u32> {
        Ok(BinaryReader::u32_le(&self.read_bytes(4)?))
    }
    pub fn read_u64_le(&mut self) -> io::Result<u64> {
        Ok(BinaryReader::u64_le(&self.read_bytes(8)?))
    }
    pub fn read_compact_u64_le(&mut self, width: usize) -> io::Result<u64> {
        BinaryReader::compact_u64_le(&self.read_bytes(width)?)
    }
}
