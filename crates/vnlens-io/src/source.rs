//! Independent cursors over mapped or transformed random-access sources.
#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use crate::{ArcView, BinaryIo, BinaryReader};

/// A byte source whose ranges can be requested without materializing its body.
pub trait ReadAt: Send + Sync {
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>>;
    /// Creates an independent, cancellable cursor. Transformed sources override
    /// this to retain their decoder state across sequential reads.
    fn reader(self: Arc<Self>, cancelled: Arc<AtomicBool>) -> io::Result<Box<dyn ReadSeek>>
    where
        Self: 'static,
    {
        Ok(Box::new(SourceCursor {
            source: self,
            position: 0,
            cancelled,
        }))
    }
}

pub trait ReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeek for T {}

impl ReadAt for Arc<[u8]> {
    fn len(&self) -> u64 {
        self.as_ref().len() as u64
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        let start = usize::try_from(offset)
            .map_err(|_| BinaryIo::unexpected_eof("source offset overflow"))?;
        let end = start
            .checked_add(size)
            .ok_or_else(|| BinaryIo::unexpected_eof("source range overflow"))?;
        self.get(start..end)
            .map(Cow::Borrowed)
            .ok_or_else(|| BinaryIo::unexpected_eof("source exceeds data"))
    }
}

/// A bounded view into another source; retains its owner without copying bytes.
pub struct RangeSource {
    source: Arc<dyn ReadAt>,
    offset: u64,
    size: u64,
}
impl std::fmt::Debug for RangeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RangeSource")
            .field("offset", &self.offset)
            .field("size", &self.size)
            .finish()
    }
}
impl RangeSource {
    pub fn new(source: Arc<dyn ReadAt>, offset: u64, size: u64) -> io::Result<Self> {
        if offset > source.len() || size > source.len() - offset {
            return Err(BinaryIo::unexpected_eof("range exceeds source"));
        }
        Ok(Self {
            source,
            offset,
            size,
        })
    }
}
impl ReadAt for RangeSource {
    fn len(&self) -> u64 {
        self.size
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        if offset > self.size || size as u64 > self.size - offset {
            return Err(BinaryIo::unexpected_eof("read exceeds range"));
        }
        let start = self
            .offset
            .checked_add(offset)
            .ok_or_else(|| BinaryIo::unexpected_eof("range offset overflow"))?;
        self.source.read_at(start, size)
    }
}

struct SourceCursor<T: ReadAt + ?Sized> {
    source: Arc<T>,
    position: u64,
    cancelled: Arc<AtomicBool>,
}
impl<T: ReadAt + ?Sized> Read for SourceCursor<T> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        check_cancelled(&self.cancelled)?;
        let size = buffer.len().min(
            usize::try_from(self.source.len().saturating_sub(self.position)).unwrap_or(usize::MAX),
        );
        if size == 0 {
            return Ok(0);
        }
        let bytes = self.source.read_at(self.position, size)?;
        if bytes.len() != size {
            return Err(BinaryIo::unexpected_eof("source returned a short range"));
        }
        buffer[..size].copy_from_slice(&bytes);
        self.position += size as u64;
        Ok(size)
    }
}
impl<T: ReadAt + ?Sized> Seek for SourceCursor<T> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        check_cancelled(&self.cancelled)?;
        self.position = seek_position(position, self.position, self.source.len())?;
        Ok(self.position)
    }
}

pub type ReadFactory =
    Arc<dyn Fn(Arc<AtomicBool>) -> io::Result<Box<dyn Read + Send>> + Send + Sync>;

/// Random access over a sequential transform. Small forward reads reuse one
/// decoder; backward reads replay it. Explicit cursors keep independent state.
pub struct ReplaySource {
    factory: ReadFactory,
    size: u64,
    reader: Mutex<ReplayReader>,
}

impl std::fmt::Debug for ReplaySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplaySource")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl ReplaySource {
    pub fn new(factory: ReadFactory, size: u64) -> io::Result<Self> {
        let reader = ReplayReader::new(factory.clone(), size, Arc::new(AtomicBool::new(false)))?;
        Ok(Self {
            factory,
            size,
            reader: Mutex::new(reader),
        })
    }
}

impl ReadAt for ReplaySource {
    fn len(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        if offset > self.size || size as u64 > self.size - offset {
            return Err(BinaryIo::unexpected_eof("read exceeds transformed source"));
        }
        if size == 0 {
            return Ok(Cow::Borrowed(&[]));
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(io::Error::other)?;
        bytes.resize(size, 0);
        let mut reader = self
            .reader
            .lock()
            .map_err(|_| io::Error::other("Source reader lock poisoned"))?;
        reader.seek(SeekFrom::Start(offset))?;
        let result = reader.read_exact(&mut bytes);
        if result.is_err() {
            *reader = ReplayReader::new(
                self.factory.clone(),
                self.size,
                Arc::new(AtomicBool::new(false)),
            )?;
        }
        result.map(|()| Cow::Owned(bytes))
    }

    fn reader(self: Arc<Self>, cancelled: Arc<AtomicBool>) -> io::Result<Box<dyn ReadSeek>> {
        Ok(Box::new(ReplayReader::new(
            self.factory.clone(),
            self.size,
            cancelled,
        )?))
    }
}

/// A bounded-memory cursor over a sequential transform. Forward seeks discard
/// output; backward seeks restart the transform. Length comes from the format.
pub struct ReplayReader {
    factory: ReadFactory,
    reader: Box<dyn Read + Send>,
    cancelled: Arc<AtomicBool>,
    size: u64,
    position: u64,
    decoded: u64,
    finished: bool,
}
impl std::fmt::Debug for ReplayReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayReader")
            .field("size", &self.size)
            .field("position", &self.position)
            .finish()
    }
}
impl ReplayReader {
    pub fn new(factory: ReadFactory, size: u64, cancelled: Arc<AtomicBool>) -> io::Result<Self> {
        let reader = factory(cancelled.clone())?;
        Ok(Self {
            factory,
            reader,
            cancelled,
            size,
            position: 0,
            decoded: 0,
            finished: false,
        })
    }
    fn read_decoded(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        check_cancelled(&self.cancelled)?;
        let read = self.reader.read(buffer)?;
        if read == 0 && self.decoded < self.size {
            return Err(BinaryIo::unexpected_eof(
                "transformed source ended before its declared size",
            ));
        }
        self.decoded = self
            .decoded
            .checked_add(read as u64)
            .ok_or_else(|| BinaryIo::invalid_input("decoded position overflow"))?;
        if self.decoded > self.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transform exceeds declared size",
            ));
        }
        if self.decoded == self.size && !self.finished {
            if self.reader.read(&mut [0; 1])? != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "transform exceeds declared size",
                ));
            }
            self.finished = true;
        }
        Ok(read)
    }
}
impl Read for ReplayReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        check_cancelled(&self.cancelled)?;
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.position >= self.size {
            if self.decoded == self.size && !self.finished {
                self.read_decoded(&mut [0; 1])?;
            }
            return Ok(0);
        }
        if self.position < self.decoded {
            self.reader = (self.factory)(self.cancelled.clone())?;
            self.decoded = 0;
            self.finished = false;
        }
        if self.decoded < self.position {
            let mut scratch = [0; 65536];
            while self.decoded < self.position {
                let size =
                    usize::try_from((self.position - self.decoded).min(scratch.len() as u64))
                        .map_err(io::Error::other)?;
                self.read_decoded(&mut scratch[..size])?;
            }
        }
        let size = buffer
            .len()
            .min(usize::try_from(self.size - self.position).unwrap_or(usize::MAX));
        let read = self.read_decoded(&mut buffer[..size])?;
        self.position += read as u64;
        Ok(read)
    }
}
impl Seek for ReplayReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        check_cancelled(&self.cancelled)?;
        self.position = seek_position(position, self.position, self.size)?;
        Ok(self.position)
    }
}
fn seek_position(position: SeekFrom, current: u64, size: u64) -> io::Result<u64> {
    let position = match position {
        SeekFrom::Start(position) => return Ok(position),
        SeekFrom::Current(offset) => i128::from(current) + i128::from(offset),
        SeekFrom::End(offset) => i128::from(size) + i128::from(offset),
    };
    u64::try_from(position).map_err(|_| BinaryIo::invalid_input("seek position is out of range"))
}
fn check_cancelled(cancelled: &AtomicBool) -> io::Result<()> {
    if cancelled.load(Ordering::Relaxed) {
        Err(io::Error::other("Source reading was cancelled"))
    } else {
        Ok(())
    }
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

#[cfg(test)]
#[path = "../tests/source.rs"]
mod tests;
