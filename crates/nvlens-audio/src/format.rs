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
fn selected(tag: &str) -> Result<Box<dyn AudioFormat>> {
    for registration in nvlens_core::inventory::iter::<AudioRegistration>() {
        let format = (registration.0)();
        if format.tag() == tag {
            return Ok(format);
        }
    }
    Err(Error::Unsupported(format!(
        "Audio route is not registered: {tag}"
    )))
}
/// Reads metadata using exactly the selected format; never probes another reader.
pub fn metadata_as(tag: &str, data: &[u8]) -> Result<Option<AudioMeta>> {
    selected(tag)?.metadata(data)
}
pub fn decode_as(tag: &str, data: &[u8]) -> Result<Pcm> {
    decode_cancellable_as(tag, data, &AtomicBool::new(false))
}
/// Decodes the selected audio format, returning Cancelled when requested.
pub fn decode_cancellable_as(tag: &str, data: &[u8], cancelled: &AtomicBool) -> Result<Pcm> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    selected(tag)?.decode_cancellable(data, cancelled)
}
