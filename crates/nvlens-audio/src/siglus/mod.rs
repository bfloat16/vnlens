//! NWA audio: 44-byte LE header, absolute block offsets, independent channel
//! predictors and LSB-first signed-magnitude deltas. Verified against the
//! mono/stereo decoders sub_71E9C0/sub_71F880. Levels 0..5 select delta widths;
//! -1 stores PCM directly. Run lengths span interleaved channel samples.
use crate::{AudioFormat, AudioMeta, AudioRegistration, Pcm};
use nvlens_core::{Error, Format, Result};
use nvlens_io::{BinaryIo, BinaryReader, BitOrder, BitReader};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
struct Header {
    channels: u16,
    bits: u16,
    rate: u32,
    level: i32,
    rle: bool,
    blocks: u32,
    pcm_size: u32,
    packed_size: u32,
    samples: u32,
    block_samples: u32,
    final_samples: u32,
}
impl Header {
    fn parse(data: &[u8]) -> Result<Option<Self>> {
        if data.len() < 4
            || !matches!(BinaryReader::u16_le(data), 1 | 2)
            || !matches!(BinaryReader::u16_le(&data[2..]), 8 | 16)
        {
            return Ok(None);
        }
        let mut r = BinaryReader::new(data);
        let h = Self {
            channels: r.read_u16_le()?,
            bits: r.read_u16_le()?,
            rate: r.read_u32_le()?,
            level: r.read_u32_le()? as i32,
            rle: r.read_u32_le()? != 0,
            blocks: r.read_u32_le()?,
            pcm_size: r.read_u32_le()?,
            packed_size: r.read_u32_le()?,
            samples: r.read_u32_le()?,
            block_samples: r.read_u32_le()?,
            final_samples: r.read_u32_le()?,
        };
        r.read_u32_le()?; // Encoder's estimated compressed block size.
        if !(-1..=5).contains(&h.level) {
            return Err(Error::Unsupported(format!(
                "NWA compression level {}",
                h.level
            )));
        }
        if h.rate == 0
            || u64::from(h.samples) * u64::from(h.bits / 8) != u64::from(h.pcm_size)
            || !h.samples.is_multiple_of(u32::from(h.channels))
        {
            return Err(corrupt("Inconsistent NWA PCM dimensions"));
        }
        if h.level >= 0 {
            let last = if h.final_samples == 0 {
                h.block_samples
            } else {
                h.final_samples
            };
            if h.blocks == 0
                || last > h.block_samples
                || u64::from(h.blocks - 1) * u64::from(h.block_samples) + u64::from(last)
                    != u64::from(h.samples)
            {
                return Err(corrupt("Inconsistent NWA block sample counts"));
            }
        }
        Ok(Some(h))
    }
    fn meta(&self) -> AudioMeta {
        AudioMeta {
            codec: "NWA",
            channels: self.channels,
            sample_rate: self.rate,
            frames: Some(u64::from(self.samples) / u64::from(self.channels)),
        }
    }
}
fn corrupt(reason: &str) -> Error {
    Error::Corrupt {
        offset: 0,
        reason: reason.into(),
    }
}
#[derive(Debug, Default)]
struct Nwa;
impl Format for Nwa {
    fn tag(&self) -> &'static str {
        "nwa/siglus"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["nwa"]
    }
    fn description(&self) -> &'static str {
        "Siglus/RealLive NWA audio"
    }
}
impl AudioFormat for Nwa {
    fn metadata(&self, data: &[u8]) -> Result<Option<AudioMeta>> {
        Ok(Header::parse(data)?.map(|h| h.meta()))
    }
    fn decode(&self, data: &[u8]) -> Result<Pcm> {
        self.decode_cancellable(data, &AtomicBool::new(false))
    }
    fn decode_cancellable(&self, data: &[u8], cancel: &AtomicBool) -> Result<Pcm> {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let h = Header::parse(data)?.ok_or(Error::InvalidFormat)?;
        let mut output = Vec::new();
        if h.level == -1 {
            let mut r = BinaryReader::new_at(data, 44)?;
            let mut pcm = BinaryReader::new(r.read_bytes(h.pcm_size as usize)?);
            for i in 0..h.samples {
                if i.is_multiple_of(4096) && cancel.load(Ordering::Relaxed) {
                    return Err(Error::Cancelled);
                }
                output.push(if h.bits == 8 {
                    (f32::from(pcm.read_u8()?) - 128.0) / 128.0
                } else {
                    f32::from(pcm.read_u16_le()? as i16) / 32768.0
                });
            }
        } else {
            let end =
                usize::try_from(h.packed_size).map_err(|_| corrupt("NWA size exceeds memory"))?;
            let data = data
                .get(..end)
                .ok_or_else(|| BinaryIo::unexpected_eof("Truncated NWA payload"))?;
            let index_end = 44 + u64::from(h.blocks) * 4;
            let index_len = usize::try_from(u64::from(h.blocks) * 4)
                .map_err(|_| corrupt("NWA index exceeds memory"))?;
            let mut r = BinaryReader::new_at(data, 44)?;
            let mut index = BinaryReader::new(r.read_bytes(index_len)?);
            let mut start = index.read_u32_le()?;
            for block in 0..h.blocks {
                if cancel.load(Ordering::Relaxed) {
                    return Err(Error::Cancelled);
                }
                let next = if block + 1 < h.blocks {
                    index.read_u32_le()?
                } else {
                    h.packed_size
                };
                if u64::from(start) < index_end || next < start {
                    return Err(corrupt("Invalid NWA block range"));
                }
                let bytes = data
                    .get(start as usize..next as usize)
                    .ok_or_else(|| BinaryIo::unexpected_eof("NWA block exceeds file"))?;
                let count = if block + 1 == h.blocks && h.final_samples != 0 {
                    h.final_samples
                } else {
                    h.block_samples
                };
                decode_block(bytes, count, &h, &mut output, cancel)?;
                start = next;
            }
        }
        Ok(Pcm {
            meta: h.meta(),
            samples: output.into(),
        })
    }
}
fn decode_block(
    data: &[u8],
    count: u32,
    h: &Header,
    output: &mut Vec<f32>,
    cancel: &AtomicBool,
) -> Result<()> {
    let mut r = BinaryReader::new(data);
    let mut predictors = [0i16; 2];
    for p in &mut predictors[..usize::from(h.channels)] {
        *p = if h.bits == 8 {
            i16::from(r.read_u8()?)
        } else {
            r.read_u16_le()? as i16
        };
    }
    let mut bits = BitReader::new(r.read_bytes(r.remaining())?, BitOrder::Lsb);
    let mut repeats = 0;
    for i in 0..count {
        if i.is_multiple_of(4096) && cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let p = &mut predictors[(i % u32::from(h.channels)) as usize];
        if repeats > 0 {
            repeats -= 1;
        } else {
            let control = bits.read_bits_le(3)?;
            let delta = if control == 7 {
                if bits.read_bit()? != 0 {
                    *p = 0;
                    None
                } else {
                    Some(if h.level < 3 {
                        (8 - h.level, 9 + h.level)
                    } else {
                        (8, 9)
                    })
                }
            } else if control > 0 {
                Some(if h.level < 3 {
                    (5 - h.level, 2 + control as i32 + h.level)
                } else {
                    (3 + h.level, 1 + control as i32)
                })
            } else {
                if h.rle && bits.read_bit()? != 0 {
                    repeats = bits.read_bits_le(2)?;
                    if repeats == 3 {
                        repeats = bits.read_bits_le(8)?;
                    }
                }
                None
            };
            if let Some((width, shift)) = delta {
                let value = bits.read_bits_le(width as u8)?;
                let sign = 1 << (width - 1);
                let magnitude = ((value & (sign - 1)) << shift) as i16;
                *p = if value & sign == 0 {
                    p.wrapping_add(magnitude)
                } else {
                    p.wrapping_sub(magnitude)
                };
            }
        }
        output.push(if h.bits == 8 {
            (f32::from(*p as u8) - 128.0) / 128.0
        } else {
            f32::from(*p) / 32768.0
        });
    }
    Ok(())
}
nvlens_core::inventory::submit! { AudioRegistration(||Box::new(Nwa)) }

#[cfg(test)]
#[path = "../../tests/siglus/mod.rs"]
mod tests;
