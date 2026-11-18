//! nbzplgin.dll::expand: BE u32 original length followed by a bzip2 stream.
//! The plugin's audio output is a complete WAV; sample decoding is shared.
use crate::{AudioFormat, AudioMeta, AudioRegistration, Pcm, standard::StandardAudio};
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{Error, Format, Result};
use vnlens_io::BinaryReader;

#[derive(Debug, Default)]
struct Nbz;
impl Format for Nbz {
    fn tag(&self) -> &'static str {
        "nbz/nscripter"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["nbz"]
    }
    fn description(&self) -> &'static str {
        "NScripter NBZ bzip2 audio"
    }
}
impl AudioFormat for Nbz {
    fn metadata(&self, data: &[u8]) -> Result<Option<AudioMeta>> {
        StandardAudio.metadata(&decode_envelope(data)?)
    }
    fn decode(&self, data: &[u8]) -> Result<Pcm> {
        self.decode_cancellable(data, &AtomicBool::new(false))
    }
    fn decode_cancellable(&self, data: &[u8], cancelled: &AtomicBool) -> Result<Pcm> {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        StandardAudio.decode_cancellable(&decode_envelope(data)?, cancelled)
    }
}
/// Removes the NBZ length/bzip2 envelope, retaining the embedded resource's
/// bytes. Archive callers use this before domain routing; disk audio callers
/// subsequently select the WAV decoder. No DLL is loaded or executed.
pub fn decode_envelope(data: &[u8]) -> Result<Vec<u8>> {
    let mut r = BinaryReader::new(data);
    let size = usize::try_from(BinaryReader::u32_be(r.read_bytes(4)?))
        .map_err(|_| Error::Unsupported("NBZ size exceeds address space".into()))?;
    vnlens_crypto::compress::bzip2::decompress(r.read_bytes(r.remaining())?, size).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            e.into()
        } else {
            Error::Corrupt {
                offset: 4,
                reason: format!("NBZ bzip2: {e}"),
            }
        }
    })
}
vnlens_core::inventory::submit! {AudioRegistration(|| Box::new(Nbz))}

#[cfg(test)]
#[path = "../../tests/nscripter/mod.rs"]
mod tests;
