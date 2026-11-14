//! CRI HCA metadata and spectral decoding come from middleware; FFmpeg
//! decodes ADX PCM. HCA's
//! encoder delay and end padding are removed according to its native header.
use crate::{AudioFormat, AudioMeta, AudioRegistration, Pcm};
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{Error, Format, Result};
use vnlens_io::BinaryIo;
use vnlens_middleware::criware::audio::{AdxHeader, HcaHeader};

#[derive(Debug, Default)]
struct Hca;
impl Format for Hca {
    fn tag(&self) -> &'static str {
        "cri/hca"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x00414348, 0x00c1c3c8]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["hca"]
    }
    fn description(&self) -> &'static str {
        "CRIWARE HCA audio"
    }
}
fn hca_meta(header: &HcaHeader) -> AudioMeta {
    AudioMeta {
        codec: "HCA",
        channels: header.channels,
        sample_rate: header.sample_rate,
        frames: Some(header.frames),
    }
}

fn adx_meta(header: &AdxHeader) -> AudioMeta {
    AudioMeta {
        codec: "ADX",
        channels: header.channels,
        sample_rate: header.sample_rate,
        frames: Some(header.frames),
    }
}

impl AudioFormat for Hca {
    fn metadata(&self, data: &[u8]) -> Result<Option<AudioMeta>> {
        Ok(Some(hca_meta(&HcaHeader::open(data)?)))
    }
    fn decode(&self, data: &[u8]) -> Result<Pcm> {
        self.decode_cancellable(data, &AtomicBool::new(false))
    }
    fn decode_cancellable(&self, data: &[u8], cancel: &AtomicBool) -> Result<Pcm> {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let header = HcaHeader::open(data)?;
        let mut decoder = vnlens_middleware::criware::hca::Decoder::new(header.clone())?;
        let count = usize::try_from(header.block_count).map_err(|_| {
            Error::Unsupported("HCA block count cannot fit in address space".into())
        })?;
        let block_size = usize::from(header.block_size);
        let length = count
            .checked_mul(block_size)
            .ok_or_else(|| BinaryIo::unexpected_eof("HCA data size overflow"))?;
        let at = usize::from(header.header_size);
        let end = at
            .checked_add(length)
            .ok_or_else(|| BinaryIo::unexpected_eof("HCA data end overflow"))?;
        let blocks = data
            .get(at..end)
            .ok_or_else(|| BinaryIo::unexpected_eof("Truncated HCA block data"))?;
        let meta = hca_meta(&header);
        let channels = usize::from(header.channels);
        let first = u64::from(header.delay);
        let last = first + header.frames;
        let mut samples = Vec::new();
        for (index, block) in blocks.chunks_exact(block_size).enumerate() {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let decoded = decoder.decode_frame(block)?;
            let base = index as u64 * 1024;
            let start = first.saturating_sub(base).min(1024) as usize;
            let stop = last.saturating_sub(base).min(1024) as usize;
            if stop > start {
                samples.extend_from_slice(&decoded[start * channels..stop * channels]);
            }
        }
        Ok(Pcm {
            meta,
            samples: samples.into(),
        })
    }
}
#[derive(Debug, Default)]
struct Adx;
impl Format for Adx {
    fn tag(&self) -> &'static str {
        "cri/adx"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["adx"]
    }
    fn description(&self) -> &'static str {
        "CRIWARE ADX audio"
    }
}
impl AudioFormat for Adx {
    fn metadata(&self, data: &[u8]) -> Result<Option<AudioMeta>> {
        Ok(Some(adx_meta(&AdxHeader::open(data)?)))
    }
    fn decode(&self, data: &[u8]) -> Result<Pcm> {
        self.decode_cancellable(data, &AtomicBool::new(false))
    }
    fn decode_cancellable(&self, data: &[u8], cancel: &AtomicBool) -> Result<Pcm> {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let header = AdxHeader::open(data)?;
        if matches!(header.cipher, 8 | 9) {
            return Err(Error::UnknownScheme(Some(
                "Encrypted ADX requires resolved CRIWARE key parameters".into(),
            )));
        }
        if header.cipher != 0 {
            return Err(Error::Unsupported(format!(
                "ADX cipher flags {}",
                header.cipher
            )));
        }
        let meta = adx_meta(&header);
        let pcm = crate::ffmpeg::decode(data, "audio.adx", meta.clone(), cancel)?;
        let size = usize::try_from(header.frames)
            .ok()
            .and_then(|n| n.checked_mul(usize::from(header.channels)))
            .ok_or_else(|| BinaryIo::unexpected_eof("ADX sample count overflow"))?;
        let samples = pcm
            .samples
            .get(..size)
            .ok_or_else(|| BinaryIo::unexpected_eof("ADX decoder returned too few samples"))?;
        Ok(Pcm {
            meta,
            samples: samples.into(),
        })
    }
}
vnlens_core::inventory::submit! { AudioRegistration(|| Box::new(Hca)) }
vnlens_core::inventory::submit! { AudioRegistration(|| Box::new(Adx)) }

#[cfg(test)]
#[path = "../../tests/criware/mod.rs"]
mod tests;
