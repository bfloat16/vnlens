//! Standard audio carried by engine archives, including YU-RIS Ogg/WAV.
mod ogg;
mod wav;
use crate::{AudioFormat, AudioMeta, AudioRegistration, Pcm};
use nvlens_core::{Format, Result};
use std::sync::atomic::AtomicBool;
const SIGNATURES: &[u32] = &[0x5367_674f, 0x4646_4952, 0x3436_4652];
#[derive(Debug, Default)]
struct StandardAudio;
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
        "Ogg Vorbis and PCM WAV audio"
    }
}
impl AudioFormat for StandardAudio {
    fn metadata(&self, data: &[u8]) -> Result<Option<AudioMeta>> {
        if data.starts_with(b"OggS") {
            ogg::metadata(data).map(Some)
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
            ogg::decode(data, cancelled)
        } else {
            wav::decode(data, cancelled)
        }
    }
}
nvlens_core::inventory::submit! {AudioRegistration(||Box::new(StandardAudio))}
