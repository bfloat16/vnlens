//! MPEG Layer III streams. FFmpeg reads stream properties and decodes frames;
//! this registration is selected explicitly by the host's MP3 route.
use crate::{AudioFormat, AudioMeta, AudioRegistration, Pcm};
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{Error, Format, Result};

#[derive(Debug, Default)]
struct Mp3;
impl Format for Mp3 {
    fn tag(&self) -> &'static str {
        "audio/mpeg"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["mp3"]
    }
    fn description(&self) -> &'static str {
        "MPEG Layer III audio"
    }
}
impl AudioFormat for Mp3 {
    fn metadata(&self, data: &[u8]) -> Result<Option<AudioMeta>> {
        crate::ffmpeg::metadata(data, "sound.mp3", ffmpeg_next::codec::Id::MP3, "MP3").map(Some)
    }
    fn decode(&self, data: &[u8]) -> Result<Pcm> {
        self.decode_cancellable(data, &AtomicBool::new(false))
    }
    fn decode_cancellable(&self, data: &[u8], cancel: &AtomicBool) -> Result<Pcm> {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let meta = self.metadata(data)?.ok_or(Error::InvalidFormat)?;
        crate::ffmpeg::decode(data, "sound.mp3", meta, cancel)
    }
}
vnlens_core::inventory::submit! { AudioRegistration(|| Box::new(Mp3)) }

#[cfg(test)]
#[path = "../../tests/standard/mpeg.rs"]
mod tests;
