//! YPF payload streams. Stored-byte MurmurHash2 and zlib lengths are verified
//! while reading; rewind replays decompression with constant payload memory.

use nvlens_core::Error;
use nvlens_crypto::{compress::zlib, hash::murmur2::Murmur2};
use nvlens_io::{ReadAt, ReadSeek, ReplayReader};
use std::{
    borrow::Cow,
    io::{self, Read, Seek, SeekFrom},
    sync::{Arc, atomic::AtomicBool},
};

#[derive(Clone)]
pub(super) struct YpfSource {
    pub source: Arc<dyn ReadAt>,
    pub packed: bool,
    pub size: u64,
    pub checksum: u32,
    pub offset: u64,
}
impl ReadAt for YpfSource {
    fn len(&self) -> u64 {
        self.size
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        if offset > self.size || size as u64 > self.size - offset {
            return Err(nvlens_io::BinaryIo::unexpected_eof(
                "YPF stream range exceeds entry",
            ));
        }
        let mut reader = Arc::new(self.clone()).reader(Arc::new(AtomicBool::new(false)))?;
        reader.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; size];
        reader.read_exact(&mut bytes)?;
        Ok(Cow::Owned(bytes))
    }
    fn reader(self: Arc<Self>, cancelled: Arc<AtomicBool>) -> io::Result<Box<dyn ReadSeek>> {
        let size = self.size;
        let factory = Arc::new(move |cancelled| -> io::Result<Box<dyn Read + Send>> {
            let reader = Stored {
                reader: self.source.clone().reader(cancelled)?,
                remaining: self.source.len(),
                hash: Murmur2::new(self.source.len(), 0),
                checksum: self.checksum,
                offset: self.offset,
            };
            Ok(if self.packed {
                Box::new(Inflated(zlib::decoder(reader)))
            } else {
                Box::new(reader)
            })
        });
        Ok(Box::new(ReplayReader::new(factory, size, cancelled)?))
    }
}
struct Stored {
    reader: Box<dyn ReadSeek>,
    remaining: u64,
    hash: Murmur2,
    checksum: u32,
    offset: u64,
}
impl Read for Stored {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let read = self.reader.read(buffer)?;
        if read == 0 && self.remaining != 0 {
            return Err(nvlens_io::BinaryIo::unexpected_eof(
                "YPF stored payload is truncated",
            ));
        }
        self.hash.update(&buffer[..read]);
        self.remaining = self
            .remaining
            .checked_sub(read as u64)
            .ok_or_else(|| io::Error::other("YPF stored length overflow"))?;
        if self.remaining == 0 && self.hash.clone().finish() != self.checksum {
            return Err(io::Error::other(Error::Corrupt {
                offset: self.offset,
                reason: "YPF stored payload hash mismatch".into(),
            }));
        }
        Ok(read)
    }
}
struct Inflated(zlib::ZlibDecoder<Stored>);
impl Read for Inflated {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.0.read(buffer)?;
        if read == 0 && !buffer.is_empty() {
            let mut scratch = [0; 65536];
            while self.0.get_mut().read(&mut scratch)? != 0 {}
        }
        Ok(read)
    }
}
