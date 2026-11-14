//! Lazy HFS0 region hashes and NCA SHA-256/IVFC block verification.
use std::{
    borrow::Cow,
    collections::BTreeSet,
    io,
    sync::{Arc, Mutex},
};
use vnlens_crypto::hash::sha256::Sha256;
use vnlens_io::{BinaryIo, ReadAt};

#[derive(Clone, Debug)]
pub(super) struct RegionHash {
    pub offset: u64,
    pub size: u64,
    pub expected: [u8; 32],
}

pub(super) struct HashedRegion {
    source: Arc<dyn ReadAt>,
    hash: RegionHash,
}
impl HashedRegion {
    pub fn new(source: Arc<dyn ReadAt>, hash: RegionHash) -> Self {
        Self { source, hash }
    }
}
impl ReadAt for HashedRegion {
    fn len(&self) -> u64 {
        self.source.len()
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        check_range(self.source.as_ref(), offset, size)?;
        if size != 0 {
            let actual = hash_range(
                self.source.as_ref(),
                self.hash.offset,
                self.hash.size,
                self.hash.size,
            )?;
            if actual != self.hash.expected {
                return Err(invalid("HFS0 SHA-256 mismatch"));
            }
        }
        self.source.read_at(offset, size)
    }
}

/// One authenticated level. Reading a child verifies its parent hash bytes
/// through the parent source before comparing this level's data block.
pub(super) struct HashLevel {
    pub source: Arc<dyn ReadAt>,
    pub hashes: Arc<dyn ReadAt>,
    pub block_size: u64,
    pub padded: bool,
    /// Sources are immutable. Cache only successful block authentication,
    /// never preload payloads or retain buffers the size of a hash block.
    pub verified: Mutex<BTreeSet<u64>>,
}
impl ReadAt for HashLevel {
    fn len(&self) -> u64 {
        self.source.len()
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        check_range(self.source.as_ref(), offset, size)?;
        if size == 0 {
            return self.source.read_at(offset, size);
        }
        let first = offset / self.block_size;
        let last = (offset + size as u64 - 1) / self.block_size;
        for index in first..=last {
            // Parent levels have independent locks; the hash tree has no
            // back-edges. Readers share verification, not a mutable cursor.
            let mut verified = self
                .verified
                .lock()
                .map_err(|_| io::Error::other("NS hash verification cache is unavailable"))?;
            if verified.contains(&index) {
                continue;
            }
            let start = index * self.block_size;
            let length = self.block_size.min(self.source.len() - start);
            let padded_length = if self.padded { self.block_size } else { length };
            let expected = self.hashes.read_at(
                index
                    .checked_mul(32)
                    .ok_or_else(|| invalid("Hash offset overflow"))?,
                32,
            )?;
            let actual = hash_range(self.source.as_ref(), start, length, padded_length)?;
            if actual.as_slice() != expected.as_ref() {
                return Err(invalid(format!(
                    "NCA SHA-256 mismatch at level offset 0x{start:x}"
                )));
            }
            verified.insert(index);
        }
        self.source.read_at(offset, size)
    }
}

pub(super) fn hash_range(
    source: &dyn ReadAt,
    offset: u64,
    size: u64,
    padded: u64,
) -> io::Result<[u8; 32]> {
    if offset > source.len() || size > source.len() - offset {
        return Err(BinaryIo::unexpected_eof("Hash region exceeds NS source"));
    }
    let mut hash = Sha256::default();
    let mut done = 0;
    while done < size {
        let length = (size - done).min(65536) as usize;
        hash.update(&source.read_at(offset + done, length)?);
        done += length as u64;
    }
    let zero = [0; 4096];
    while done < padded {
        let length = (padded - done).min(zero.len() as u64) as usize;
        hash.update(&zero[..length]);
        done += length as u64;
    }
    Ok(hash.finish())
}

fn check_range(source: &dyn ReadAt, offset: u64, size: usize) -> io::Result<()> {
    if offset > source.len() || size as u64 > source.len() - offset {
        return Err(BinaryIo::unexpected_eof("NS read exceeds source"));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
