//! Standard audio carried by engine archives, including YU-RIS Ogg/WAV.
pub(crate) mod ogg;
mod opus;
mod wav;
use crate::{AudioFormat, AudioMeta, AudioRegistration, Pcm};
use std::sync::atomic::AtomicBool;
use vnlens_core::{Format, Result};
const SIGNATURES: &[u32] = &[0x5367_674f, 0x4646_4952, 0x3436_4652];
#[derive(Debug, Default)]
pub(crate) struct StandardAudio;
impl Format for StandardAudio {
    fn tag(&self) -> &'static str {
        "audio/standard"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["ogg", "wav"]
    }
    fn description(&self) -> &'static str {
        "Ogg Vorbis, Ogg Opus and PCM WAV audio"
    }
}
impl AudioFormat for StandardAudio {
    fn metadata(&self, data: &[u8]) -> Result<Option<AudioMeta>> {
        if data.starts_with(b"OggS") {
            if opus::recognizes(data)? {
                opus::metadata(data).map(Some)
            } else {
                ogg::metadata(data).map(Some)
            }
        } else if (data.starts_with(b"RIFF") || data.starts_with(b"RF64"))
            && data.get(8..12) == Some(b"WAVE")
        {
            wav::metadata(data).map(Some)
        } else {
            Ok(None)
        }
    }
    fn decode(&self, data: &[u8]) -> Result<Pcm> {
        self.decode_cancellable(data, &AtomicBool::new(false))
    }
    fn decode_cancellable(&self, data: &[u8], cancelled: &AtomicBool) -> Result<Pcm> {
        if data.starts_with(b"OggS") {
            if opus::recognizes(data)? {
                opus::decode(data, cancelled)
            } else {
                ogg::decode(data, cancelled)
            }
        } else {
            wav::decode(data, cancelled)
        }
    }
}
vnlens_core::inventory::submit! {AudioRegistration(||Box::new(StandardAudio))}
