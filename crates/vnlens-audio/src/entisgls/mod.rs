//! MIO audio adapter. ERISA framing and LOT/PCM state are shared with MEI
//! movie audio; this domain exposes PCM metadata and cancellable full decode.
use crate::{AudioFormat, AudioMeta, AudioRegistration, Pcm};
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{Error, Format, Result};
use vnlens_middleware::erisa::{MediaFile, SoundChunk, SoundDecoder, SoundInfo, sound_chunks};

#[derive(Debug, Default)]
struct Mio;
impl Format for Mio {
    fn tag(&self) -> &'static str {
        "mio/entisgls"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x6974_6e45]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["mio"]
    }
    fn description(&self) -> &'static str {
        "Music Interleaved and Orthogonal audio"
    }
}
fn open(data: &[u8]) -> Result<(SoundInfo, Vec<SoundChunk>)> {
    let file = MediaFile::open(&data)?;
    if !file.description.starts_with("Music Interleaved") {
        return Err(Error::InvalidFormat);
    }
    let info = SoundInfo::read(&file, &data)?.ok_or_else(|| Error::Corrupt {
        offset: 64,
        reason: "Missing MIO SoundInf".into(),
    })?;
    Ok((info, sound_chunks(&file, &data)?))
}
fn meta(info: &SoundInfo, chunks: &[SoundChunk]) -> AudioMeta {
    AudioMeta {
        codec: "mio",
        channels: info.channels,
        sample_rate: info.sample_rate,
        frames: Some(
            chunks
                .last()
                .map_or(0, |c| c.first_sample + u64::from(c.samples)),
        ),
    }
}
impl AudioFormat for Mio {
    fn metadata(&self, data: &[u8]) -> Result<Option<AudioMeta>> {
        let (info, chunks) = open(data)?;
        Ok(Some(meta(&info, &chunks)))
    }
    fn decode(&self, data: &[u8]) -> Result<Pcm> {
        self.decode_cancellable(data, &AtomicBool::new(false))
    }
    fn decode_cancellable(&self, data: &[u8], cancel: &AtomicBool) -> Result<Pcm> {
        let (info, chunks) = open(data)?;
        let metadata = meta(&info, &chunks);
        let mut decoder = SoundDecoder::new(info)?;
        let mut samples = Vec::new();
        for chunk in &chunks {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            samples.extend(decoder.decode(&data, &chunk.section, cancel)?);
        }
        if metadata.frames != Some(samples.len() as u64 / u64::from(metadata.channels)) {
            return Err(Error::Corrupt {
                offset: 64,
                reason: "MIO declared and decoded sample counts differ".into(),
            });
        }
        Ok(Pcm {
            meta: metadata,
            samples: samples.into(),
        })
    }
}
vnlens_core::inventory::submit! { AudioRegistration(|| Box::new(Mio)) }

#[cfg(test)]
#[path = "../../tests/entisgls/mod.rs"]
mod tests;
