//! RIFF xWMA (fmt/dpds/data), as stored in M2 sound_archive PSBs.
//! FFmpeg handles WMA packet decoding; output retains the original rate/channels.
use crate::{AudioFormat, AudioMeta, AudioRegistration, Pcm};
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{Error, Format, Result};
use vnlens_io::BinaryReader;
#[derive(Debug, Default)]
struct Xwma;
impl Format for Xwma {
    fn tag(&self) -> &'static str {
        "xwma"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x4646_4952]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["xwma"]
    }
    fn description(&self) -> &'static str {
        "RIFF xWMA audio"
    }
}
impl AudioFormat for Xwma {
    fn metadata(&self, data: &[u8]) -> Result<Option<AudioMeta>> {
        if !data.starts_with(b"RIFF") || data.get(8..12) != Some(b"XWMA") {
            return Ok(None);
        }
        let mut r = BinaryReader::new(data);
        r.read_bytes(4)?;
        if u64::from(r.read_u32_le()?) + 8 != data.len() as u64 {
            return Err(bad("xWMA RIFF size mismatch"));
        }
        r.read_bytes(4)?;
        let mut meta = None;
        while r.remaining() != 0 {
            let name = r.read_bytes(4)?;
            let size = r.read_u32_le()? as usize;
            let chunk = r.read_bytes(size)?;
            if !size.is_multiple_of(2) {
                r.read_u8()?;
            }
            if name == b"fmt " {
                let mut f = BinaryReader::new(chunk);
                let codec = f.read_u16_le()?;
                let channels = f.read_u16_le()?;
                let sample_rate = f.read_u32_le()?;
                if channels == 0 || sample_rate == 0 {
                    return Err(bad("Invalid xWMA channel/rate fields"));
                }
                if !matches!(codec, 0x161 | 0x162) {
                    return Err(Error::Unsupported(format!("xWMA codec {codec:#x}")));
                }
                meta = Some(AudioMeta {
                    codec: "xWMA",
                    channels,
                    sample_rate,
                    frames: None,
                });
            }
        }
        meta.map(Some)
            .ok_or_else(|| bad("Missing xWMA format chunk"))
    }
    fn decode(&self, data: &[u8]) -> Result<Pcm> {
        self.decode_cancellable(data, &AtomicBool::new(false))
    }
    fn decode_cancellable(&self, data: &[u8], cancel: &AtomicBool) -> Result<Pcm> {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let meta = self.metadata(data)?.ok_or(Error::InvalidFormat)?;
        crate::ffmpeg::decode(data, "sound.xwma", meta, cancel)
    }
}
fn bad(reason: &str) -> Error {
    Error::Corrupt {
        offset: 0,
        reason: reason.into(),
    }
}
vnlens_core::inventory::submit! {AudioRegistration(||Box::new(Xwma))}

#[cfg(test)]
#[path = "../tests/xwma.rs"]
mod tests;
