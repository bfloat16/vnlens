//! RIFF/RF64 WAVE chunks; integer PCM and IEEE float samples.
use crate::{AudioMeta, Pcm};
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{Error, Result};
use vnlens_io::BinaryReader;

fn parse(data: &[u8]) -> Result<(AudioMeta, u16, u16, Vec<&[u8]>)> {
    let mut r = BinaryReader::new(data);
    let signature = r.read_bytes(4)?;
    let size = r.read_u32_le()?;
    if !matches!(signature, b"RIFF" | b"RF64") || r.read_bytes(4)? != b"WAVE" {
        return Err(Error::InvalidFormat);
    }
    if signature == b"RIFF" && u64::from(size) + 8 != data.len() as u64 {
        return Err(corrupt("RIFF size mismatch"));
    }
    let mut format = None;
    let mut chunks = Vec::new();
    let mut data_size64 = None;
    while r.remaining() != 0 {
        let name = r.read_bytes(4)?;
        let size = r.read_u32_le()?;
        let size = if name == b"data" && size == u32::MAX {
            data_size64.ok_or_else(|| corrupt("Missing RF64 ds64 chunk"))?
        } else {
            u64::from(size)
        };
        let size = usize::try_from(size).map_err(|_| corrupt("WAV chunk exceeds address space"))?;
        let bytes = r.read_bytes(size)?;
        if size & 1 != 0 {
            r.read_u8()?;
        }
        if name == b"ds64" {
            let mut d = BinaryReader::new(bytes);
            d.read_u64_le()?;
            data_size64 = Some(d.read_u64_le()?);
        } else if name == b"fmt " {
            let mut f = BinaryReader::new(bytes);
            let mut codec = f.read_u16_le()?;
            let channels = f.read_u16_le()?;
            let rate = f.read_u32_le()?;
            f.read_u32_le()?;
            let align = f.read_u16_le()?;
            let bits = f.read_u16_le()?;
            if codec == 0xfffe {
                f.read_bytes(8)?;
                codec = f.read_u16_le()?;
            }
            if channels == 0
                || rate == 0
                || u32::from(align) != u32::from(channels) * u32::from(bits).div_ceil(8)
            {
                return Err(corrupt("Invalid PCM format layout"));
            }
            if !matches!((codec, bits), (1, 8 | 16 | 24 | 32) | (3, 32 | 64)) {
                return Err(Error::Unsupported(format!(
                    "WAV codec {codec}, {bits} bits"
                )));
            }
            format = Some((
                AudioMeta {
                    codec: "WAV PCM",
                    channels,
                    sample_rate: rate,
                    frames: None,
                },
                codec,
                bits,
            ));
        } else if name == b"data" {
            chunks.push(bytes);
        }
    }
    let (mut meta, codec, bits) = format.ok_or_else(|| corrupt("Missing WAV format chunk"))?;
    let align = usize::from(meta.channels) * usize::from(bits) / 8;
    if chunks
        .iter()
        .any(|chunk| !chunk.len().is_multiple_of(align))
    {
        return Err(corrupt("Incomplete WAV sample frame"));
    }
    meta.frames = Some(
        chunks
            .iter()
            .map(|chunk| (chunk.len() / align) as u64)
            .sum(),
    );
    Ok((meta, codec, bits, chunks))
}
pub(crate) fn metadata(data: &[u8]) -> Result<AudioMeta> {
    Ok(parse(data)?.0)
}
pub(crate) fn decode(data: &[u8], cancelled: &AtomicBool) -> Result<Pcm> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    let (meta, codec, bits, chunks) = parse(data)?;
    let mut samples = Vec::new();
    for chunk in chunks {
        for (index, sample) in chunk.chunks_exact(usize::from(bits) / 8).enumerate() {
            if index.is_multiple_of(4096) && cancelled.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let value = if codec == 3 {
                if bits == 32 {
                    BinaryReader::f32_le(sample)
                } else {
                    BinaryReader::f64_le(sample) as f32
                }
            } else if bits == 8 {
                (f32::from(sample[0]) - 128.) / 128.
            } else {
                BinaryReader::compact_i64_le(sample)? as f32 / (1u64 << (bits - 1)) as f32
            };
            samples.push(value);
        }
    }
    Ok(Pcm {
        meta,
        samples: samples.into(),
    })
}
fn corrupt(reason: &str) -> Error {
    Error::Corrupt {
        offset: 0,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "../../tests/standard/wav.rs"]
mod tests;
