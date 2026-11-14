//! GSS OPU is Nintendo's Opus stream container: LE 0x80000001 header,
//! version/channel/pre-skip/rate/data-offset fields and a 0x80000004 data
//! chunk. Packets use BE length and final-range words, then raw RFC 6716 data.
//! The game's WAVE_TBL loader (sub_5E6E0) loads WAVDATA's OPU members; Nintendo
//! codec imports supply their decoder. Pre-skip uses the declared rate's clock.
use crate::{AudioFormat, AudioMeta, AudioRegistration, Pcm};
use opus1::{Channels, OpusDecoder, SampleRate};
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{Error, Format, Result};
use vnlens_io::{BinaryReader, Endian};

#[derive(Debug, Default)]
struct Opu;
impl Format for Opu {
    fn tag(&self) -> &'static str {
        "opus/gss"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x8000_0001]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["opu"]
    }
    fn description(&self) -> &'static str {
        "GSS Nintendo Opus audio"
    }
}
impl AudioFormat for Opu {
    fn metadata(&self, data: &[u8]) -> Result<Option<AudioMeta>> {
        read(data, &AtomicBool::new(false), false).map(|(meta, _)| Some(meta))
    }
    fn decode(&self, data: &[u8]) -> Result<Pcm> {
        self.decode_cancellable(data, &AtomicBool::new(false))
    }
    fn decode_cancellable(&self, data: &[u8], cancel: &AtomicBool) -> Result<Pcm> {
        let (meta, samples) = read(data, cancel, true)?;
        Ok(Pcm {
            meta,
            samples: samples.into(),
        })
    }
}
vnlens_core::inventory::submit! { AudioRegistration(|| Box::new(Opu)) }

fn read(data: &[u8], cancel: &AtomicBool, decode: bool) -> Result<(AudioMeta, Vec<f32>)> {
    check(cancel)?;
    let mut header = BinaryReader::new(data);
    if header.read_u32_le()? != 0x8000_0001 {
        return Err(Error::InvalidFormat);
    }
    if header.read_u32_le()? != 0x18 {
        return Err(Error::Unsupported("Nintendo Opus header layout".into()));
    }
    if header.read_u8()? != 0 {
        return Err(Error::Unsupported("Nintendo Opus version".into()));
    }
    let channels = header.read_u8()?;
    let layout = Channels::try_from(usize::from(channels))
        .map_err(|_| Error::Unsupported("Nintendo Opus multistream channel layout".into()))?;
    let skip = u64::from(header.read_u16_le()?);
    let rate = SampleRate::try_from(header.read_u32_le()?).map_err(error)?;
    let offset = header.read_u32_le()? as usize;
    header.read_bytes(4)?;
    if offset < header.position() {
        return Err(bad(16, "Nintendo Opus data overlaps header"));
    }
    let mut chunks = BinaryReader::new_at(data, offset)?;
    if chunks.read_u32_le()? != 0x8000_0004 {
        return Err(bad(offset as u64, "Invalid Nintendo Opus data chunk"));
    }
    let size = chunks.read_u32_le()? as usize;
    let mut packets = BinaryReader::new(chunks.read_bytes(size)?);
    let mut decoder = if decode {
        Some(OpusDecoder::new(rate, layout).map_err(error)?)
    } else {
        None
    };
    let mut block = if decode {
        vec![0.; rate.max_frame_size() * usize::from(channels)]
    } else {
        Vec::new()
    };
    let mut samples = Vec::new();
    let mut frames = 0u64;
    while packets.remaining() != 0 {
        check(cancel)?;
        let size = packets.read_u32(Endian::Big)? as usize;
        packets.read_u32(Endian::Big)?;
        let bytes = packets.read_bytes(size)?;
        let count = if let Some(decoder) = &mut decoder {
            decoder
                .decode(bytes, rate.max_frame_size(), &mut block)
                .map_err(error)?
        } else {
            opus1::packet::nb_samples(bytes, rate).map_err(error)?
        };
        if decode {
            let omit = skip.saturating_sub(frames).min(count as u64) as usize;
            samples.extend_from_slice(
                &block[omit * usize::from(channels)..count * usize::from(channels)],
            );
        }
        frames = frames
            .checked_add(count as u64)
            .ok_or_else(|| bad(offset as u64, "Nintendo Opus frame count overflow"))?;
    }
    let frames = frames
        .checked_sub(skip)
        .ok_or_else(|| bad(10, "Nintendo Opus pre-skip exceeds audio duration"))?;
    Ok((
        AudioMeta {
            codec: "Nintendo Opus",
            channels: u16::from(channels),
            sample_rate: rate.hz(),
            frames: Some(frames),
        },
        samples,
    ))
}
fn check(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
fn bad(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}
fn error(cause: impl std::fmt::Display) -> Error {
    bad(0, &format!("Nintendo Opus: {cause}"))
}

#[cfg(test)]
#[path = "../../tests/gss/mod.rs"]
mod tests;
