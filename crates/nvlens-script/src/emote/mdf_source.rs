//! Random access to an MDF stream without retaining unrequested decoded bytes.
//!
//! Deflate requires preceding compressed blocks to reach a requested range.
//! Forward reads retain decoder state; backward reads restart the stream.

use std::borrow::Cow;
use std::io::{self, Read};
use std::sync::{Arc, Mutex};

use nvlens_core::{Error, Result};
use nvlens_crypto::cipher::mdf::MdfStream;
use nvlens_crypto::compress::zlib;
use nvlens_io::{ArcView, BinaryIo, BinaryReader, ReadAt};

use super::mdf::{self, MdfKey};

pub(crate) struct MdfSource {
    view: Arc<ArcView>,
    len: u64,
    cipher: Option<MdfStream>,
    state: Mutex<DecodeState>,
}

struct DecodeState {
    decoder: Box<dyn Read + Send>,
    position: u64,
}

impl std::fmt::Debug for MdfSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdfSource")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl MdfSource {
    pub(crate) fn new(view: Arc<ArcView>, key: Option<MdfKey<'_>>) -> Result<Self> {
        if view.len() < 4 || !mdf::is_mdf(view.slice(0, 4)?) {
            return Err(Error::InvalidFormat);
        }
        let head = view.slice(0, 8)?;
        let len = u64::from(BinaryReader::u32_le(&head[4..]));
        let cipher = key.map(|key| MdfStream::new(key.key, key.key_len));
        let state = Mutex::new(Self::decoder(Arc::clone(&view), cipher.clone()));
        Ok(Self {
            view,
            len,
            cipher,
            state,
        })
    }

    fn decoder(view: Arc<ArcView>, cipher: Option<MdfStream>) -> DecodeState {
        let input = MdfInput {
            view,
            position: 8,
            cipher,
        };
        DecodeState {
            decoder: Box::new(zlib::decoder(input)),
            position: 0,
        }
    }
}

impl ReadAt for MdfSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        let end = offset
            .checked_add(size as u64)
            .filter(|&end| end <= self.len)
            .ok_or_else(|| {
                BinaryIo::unexpected_eof("MDF range exceeds declared original length")
            })?;
        if size == 0 {
            return Ok(Cow::Borrowed(&[]));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("MDF decoder lock poisoned"))?;
        if offset < state.position {
            *state = Self::decoder(Arc::clone(&self.view), self.cipher.clone());
        }
        let mut discard = [0u8; 8192];
        while state.position < offset {
            let take = usize::try_from((offset - state.position).min(discard.len() as u64))
                .map_err(|_| BinaryIo::unexpected_eof("MDF skip length does not fit usize"))?;
            state.decoder.read_exact(&mut discard[..take])?;
            state.position += take as u64;
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(io::Error::other)?;
        bytes.resize(size, 0);
        state.decoder.read_exact(&mut bytes)?;
        state.position = end;
        if end == self.len {
            let mut extra = [0u8; 1];
            if state.decoder.read(&mut extra)? != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "MDF decoded length exceeds its header",
                ));
            }
        }
        Ok(Cow::Owned(bytes))
    }
}

struct MdfInput {
    view: Arc<ArcView>,
    position: u64,
    cipher: Option<MdfStream>,
}

impl Read for MdfInput {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = usize::try_from((self.view.len() - self.position).min(out.len() as u64))
            .map_err(|_| BinaryIo::unexpected_eof("MDF input length does not fit usize"))?;
        out[..count].copy_from_slice(self.view.slice(self.position, count as u64)?);
        if let Some(cipher) = &mut self.cipher {
            cipher.apply(&mut out[..count]);
        }
        self.position += count as u64;
        Ok(count)
    }
}

#[cfg(test)]
#[path = "../../tests/emote/mdf_source.rs"]
mod tests;
