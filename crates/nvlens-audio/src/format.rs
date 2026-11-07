//! Audio registration and GUI-independent decoding.
use crate::{AudioMeta, Pcm};
use nvlens_core::{Error, Format, Result};
use std::sync::atomic::{AtomicBool, Ordering};
pub trait AudioFormat: Format {
    fn metadata(&self, data: &[u8]) -> Result<Option<AudioMeta>>;
    fn decode(&self, data: &[u8]) -> Result<Pcm>;
    /// Decodes with cancellation. Implementations should check between packets
    /// or sample blocks; the default preserves third-party decoder compatibility.
    fn decode_cancellable(&self, data: &[u8], cancelled: &AtomicBool) -> Result<Pcm> {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let pcm = self.decode(data)?;
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        Ok(pcm)
    }
}
#[derive(Debug)]
pub struct AudioRegistration(pub fn() -> Box<dyn AudioFormat>);
nvlens_core::inventory::collect!(AudioRegistration);
pub fn metadata(data: &[u8]) -> Result<Option<AudioMeta>> {
    for registration in nvlens_core::inventory::iter::<AudioRegistration>() {
        if let Some(meta) = (registration.0)().metadata(data)? {
            return Ok(Some(meta));
        }
    }
    Ok(None)
}
pub fn decode(data: &[u8]) -> Result<Option<Pcm>> {
    decode_cancellable(data, &AtomicBool::new(false))
}
/// Decodes a recognized audio stream, returning Cancelled when requested.
pub fn decode_cancellable(data: &[u8], cancelled: &AtomicBool) -> Result<Option<Pcm>> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    for registration in nvlens_core::inventory::iter::<AudioRegistration>() {
        let format = (registration.0)();
        if format.metadata(data)?.is_some() {
            return format.decode_cancellable(data, cancelled).map(Some);
        }
    }
    Ok(None)
}
