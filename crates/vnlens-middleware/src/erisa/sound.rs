//! MIO PCM and LOT sound blocks. SoundStm starts with u8 version, u8 flags,
//! reserved u16 and u32 sample count. Division/weight tables precede ERINA
//! coefficients; lead/post half blocks carry overlap across degree changes.
//! Verified layout follows MIODecoder::DecodeSoundDCT / DecodeSoundDCT_MSS.
use super::{MediaFile, Section, bad};
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_core::{Error, Result};
use vnlens_crypto::compress::erisa::{
    ErinaDecoder,
    transform::{Dct, inverse_lot, inverse_plot, odd_givens_inverse, revolve_parameters},
};
use vnlens_io::{BinaryReader, BitOrder, BitReader, ReadAt};

#[derive(Clone, Debug)]
pub struct SoundInfo {
    pub transformation: u32,
    pub architecture: i32,
    pub channels: u16,
    pub sample_rate: u32,
    pub degree: u32,
    pub bits: u32,
}
impl SoundInfo {
    pub fn read(file: &MediaFile, source: &dyn ReadAt) -> Result<Option<Self>> {
        let Some(section) = file.header.iter().find(|s| s.id == *b"SoundInf") else {
            return Ok(None);
        };
        let bytes = source.read_at(
            section.offset,
            usize::try_from(section.size).map_err(io::Error::other)?,
        )?;
        let mut r = BinaryReader::new(&bytes);
        r.read_u32_le()?;
        let transformation = r.read_u32_le()?;
        let architecture = r.read_u32_le()? as i32;
        let channels = r.read_u32_le()?;
        let sample_rate = r.read_u32_le()?;
        r.read_u32_le()?;
        let degree = r.read_u32_le()?;
        r.read_u32_le()?;
        let lapped_degree = r.read_u32_le()?;
        let bits = r.read_u32_le()?;
        if !matches!(channels, 1 | 2) || sample_rate == 0 {
            return Err(bad(
                section.offset + 12,
                "Invalid MIO channel count or sample rate",
            ));
        }
        if transformation == 0x0302_0000 {
            if architecture != -4 || !matches!(bits, 8 | 16) {
                return Err(Error::Unsupported(
                    "MIO PCM architecture/sample format".into(),
                ));
            }
        } else if matches!(transformation, 5 | 0x105) {
            if !matches!(architecture, -1 | -4 | -16)
                || bits != 16
                || lapped_degree != 1
                || !(8..=12).contains(&degree)
            {
                return Err(Error::Unsupported(
                    "MIO LOT architecture/degree/sample format".into(),
                ));
            }
        } else {
            return Err(Error::Unsupported(format!(
                "MIO transformation 0x{transformation:X}"
            )));
        }
        Ok(Some(Self {
            transformation,
            architecture,
            channels: channels as u16,
            sample_rate,
            degree,
            bits,
        }))
    }
}

#[derive(Clone, Debug)]
pub struct SoundChunk {
    pub section: Section,
    pub flags: u8,
    pub first_sample: u64,
    pub samples: u32,
}

/// Indexes timing and restart points using only SoundStm data headers.
pub fn sound_chunks(file: &MediaFile, source: &dyn ReadAt) -> Result<Vec<SoundChunk>> {
    let mut chunks = Vec::new();
    let mut first_sample = 0u64;
    for section in file.stream.iter().filter(|s| s.id == *b"SoundStm") {
        if section.size < 8 {
            return Err(
                vnlens_io::BinaryIo::unexpected_eof("Truncated MIO sound data header").into(),
            );
        }
        let bytes = source.read_at(section.offset, 8)?;
        let mut r = BinaryReader::new(&bytes);
        r.read_u8()?;
        let flags = r.read_u8()?;
        r.read_u16_le()?;
        let samples = r.read_u32_le()?;
        chunks.push(SoundChunk {
            section: section.clone(),
            flags,
            first_sample,
            samples,
        });
        first_sample = first_sample
            .checked_add(u64::from(samples))
            .ok_or_else(|| bad(section.offset, "MIO sample position overflow"))?;
    }
    Ok(chunks)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Lead,
    Internal,
    Post,
}
#[derive(Debug)]
struct Block {
    kind: Kind,
    degree: u32,
    channel: usize,
    weight: u32,
    coefficient: u32,
    revolve: u32,
}

#[derive(Debug)]
pub struct SoundDecoder {
    pub info: SoundInfo,
    entropy: ErinaDecoder,
    dct: Option<Dct>,
    previous: Vec<Vec<f32>>,
}
impl SoundDecoder {
    pub fn new(info: SoundInfo) -> Result<Self> {
        let dct = if info.transformation == 0x0302_0000 {
            None
        } else {
            Some(Dct::new(info.degree)?)
        };
        let previous = if dct.is_some() {
            vec![vec![0.0; 1usize << info.degree]; usize::from(info.channels)]
        } else {
            Vec::new()
        };
        Ok(Self {
            info,
            entropy: ErinaDecoder::new(false),
            dct,
            previous,
        })
    }
    pub fn decode(
        &mut self,
        source: &dyn ReadAt,
        section: &Section,
        cancel: &AtomicBool,
    ) -> Result<Vec<f32>> {
        let result = self.decode_chunk(source, section, cancel);
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        match result {
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::InvalidData => Err(bad(
                section.offset,
                &format!("MIO entropy decoding failed: {error}"),
            )),
            result => result,
        }
    }
    fn decode_chunk(
        &mut self,
        source: &dyn ReadAt,
        section: &Section,
        cancel: &AtomicBool,
    ) -> Result<Vec<f32>> {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let bytes = source.read_at(
            section.offset,
            usize::try_from(section.size).map_err(io::Error::other)?,
        )?;
        let mut r = BinaryReader::new(&bytes);
        let version = r.read_u8()?;
        let flags = r.read_u8()?;
        r.read_u16_le()?;
        let samples = usize::try_from(r.read_u32_le()?).map_err(io::Error::other)?;
        if version != 1 {
            return Err(Error::Unsupported(format!(
                "MIO sound block version {version}"
            )));
        }
        let channels = usize::from(self.info.channels);
        let mut bits = BitReader::new(r.read_bytes(r.remaining())?, BitOrder::Msb);
        if self.info.transformation == 0x0302_0000 {
            if flags & 1 != 0 {
                self.entropy = ErinaDecoder::new(false);
            }
            return self.pcm(samples, &mut bits, cancel);
        }
        if self.info.architecture == -16 {
            return Err(Error::Unsupported(
                "MIO ERISA arithmetic word coding".into(),
            ));
        }
        if bits.read_bit()? != 0 {
            return Err(bad(section.offset + 8, "Invalid MIO table separator"));
        }
        let coupled = self.info.transformation == 0x105 && channels == 2;
        let base_width = 1usize << self.info.degree;
        let subbands = samples.div_ceil(base_width);
        let mut plan = Vec::new();
        let mut divisions = vec![None; if coupled { 1 } else { channels }];
        for i in 0..subbands {
            for (channel, last) in divisions.iter_mut().enumerate() {
                let division = bits.read_bits(2)?;
                let changed = *last != Some(division);
                if changed && let Some(last) = last {
                    plan.push(block(
                        &mut bits,
                        Kind::Post,
                        self.info.degree - *last,
                        channel,
                        coupled,
                    )?);
                }
                for k in 0..1usize << division {
                    let kind = if changed && k == 0 {
                        Kind::Lead
                    } else {
                        Kind::Internal
                    };
                    plan.push(block(
                        &mut bits,
                        kind,
                        self.info.degree - division,
                        channel,
                        coupled,
                    )?);
                }
                *last = Some(division);
            }
            if i % 16 == 0 && cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
        }
        for (channel, division) in divisions.iter().enumerate() {
            if let Some(division) = division {
                plan.push(block(
                    &mut bits,
                    Kind::Post,
                    self.info.degree - division,
                    channel,
                    coupled,
                )?);
            }
        }
        if bits.read_bit()? != 0 {
            return Err(bad(section.offset + 8, "Invalid MIO coefficient separator"));
        }
        if flags & 1 != 0 {
            self.entropy = ErinaDecoder::new(false);
        }
        let all = subbands
            .checked_mul(base_width)
            .and_then(|v| v.checked_mul(channels))
            .ok_or_else(|| bad(section.offset, "MIO coefficient count overflow"))?;
        let mut encoded =
            vec![
                0;
                all.checked_mul(2)
                    .ok_or_else(|| bad(section.offset, "MIO coefficient buffer overflow"))?
            ];
        self.entropy.decode(&mut bits, &mut encoded, Some(cancel))?;
        let mut coefficients = vec![0i32; all];
        let stride = if coupled { base_width * 2 } else { base_width };
        let bands = all / stride;
        for i in 0..stride {
            for j in 0..bands {
                let src = i * bands + j;
                let low = encoded[all + src] as i8;
                let high = (encoded[src] as i8) ^ (low >> 7);
                let word = [low as u8, high as u8];
                coefficients[j * stride + i] = i32::from(BinaryReader::i16_le(&word));
            }
        }
        let mut out = vec![
            0.0;
            samples
                .checked_mul(channels)
                .ok_or_else(|| bad(section.offset, "MIO PCM count overflow"))?
        ];
        let mut written = vec![0usize; channels];
        let mut at = 0;
        for part in plan {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let width = 1usize << part.degree;
            let count = if part.kind == Kind::Internal {
                width
            } else {
                width / 2
            };
            let mut matrices = Vec::new();
            for _ in 0..if coupled { 2 } else { 1 } {
                let values = coefficients
                    .get(at..at + count)
                    .ok_or_else(|| bad(section.offset, "MIO block exceeds coefficients"))?;
                at += count;
                let values = if part.kind == Kind::Internal {
                    values.to_vec()
                } else {
                    values.iter().flat_map(|&v| [0, v]).collect()
                };
                matrices.push(dequantize(
                    &values,
                    part.degree,
                    part.weight,
                    part.coefficient,
                ));
            }
            if coupled {
                let (a, b) = matrices.split_at_mut(1);
                let (even, odd) = if part.kind == Kind::Internal {
                    (part.revolve >> 2, part.revolve & 3)
                } else {
                    (part.revolve, part.revolve)
                };
                for i in 0..width {
                    let angle =
                        f64::from(if i % 2 == 0 { even } else { odd }) * std::f64::consts::PI / 8.0;
                    let sin = angle.sin() as f32;
                    let cos = angle.cos() as f32;
                    let x = a[0][i];
                    let y = b[0][i];
                    a[0][i] = x * cos - y * sin;
                    b[0][i] = x * sin + y * cos;
                }
            }
            for (i, mut matrix) in matrices.into_iter().enumerate() {
                let channel = if coupled { i } else { part.channel };
                let params = revolve_parameters(width)?;
                odd_givens_inverse(&mut matrix, &params)?;
                if part.kind != Kind::Internal {
                    for pair in matrix.as_chunks_mut::<2>().0 {
                        pair[0] = if part.kind == Kind::Lead {
                            pair[1]
                        } else {
                            -pair[1]
                        };
                    }
                }
                inverse_plot(&mut matrix)?;
                if part.kind == Kind::Lead {
                    self.previous[channel][..width].copy_from_slice(&matrix);
                    continue;
                }
                let values = inverse_lot(&self.previous[channel][..width], &matrix)?;
                if part.kind == Kind::Internal {
                    self.previous[channel][..width].copy_from_slice(&matrix);
                }
                let values = self
                    .dct
                    .as_ref()
                    .ok_or_else(|| bad(section.offset, "MIO LOT decoder is unavailable"))?
                    .inverse(&values)?;
                let count = width.min(samples - written[channel]);
                for j in 0..count {
                    let rounded = (values[j].round() as i32).clamp(-32768, 32767);
                    out[(written[channel] + j) * channels + channel] = rounded as f32 / 32768.0;
                }
                written[channel] += count;
            }
        }
        if at != coefficients.len() || written.iter().any(|&n| n != samples) {
            return Err(bad(
                section.offset,
                "MIO block plan and sample counts differ",
            ));
        }
        Ok(out)
    }

    fn pcm(
        &mut self,
        samples: usize,
        bits: &mut BitReader<'_>,
        cancel: &AtomicBool,
    ) -> Result<Vec<f32>> {
        let channels = usize::from(self.info.channels);
        let bytes_per_sample = self.info.bits as usize / 8;
        let total = samples
            .checked_mul(channels)
            .ok_or_else(|| bad(0, "MIO PCM size overflow"))?;
        let mut encoded = vec![
            0;
            total
                .checked_mul(bytes_per_sample)
                .ok_or_else(|| bad(0, "MIO PCM bytes overflow"))?
        ];
        self.entropy.decode(bits, &mut encoded, Some(cancel))?;
        let mut out = vec![0.0; total];
        for channel in 0..channels {
            let mut value = 0i16;
            let mut delta = 0i16;
            for i in 0..samples {
                if bytes_per_sample == 1 {
                    value = value.wrapping_add(i16::from(encoded[channel * samples + i]));
                    out[i * channels + channel] = (f32::from(value as u8) - 128.0) / 128.0;
                } else {
                    let start = channel * samples * 2;
                    let low = encoded[start + samples + i] as i8;
                    let high = (encoded[start + i] as i8) ^ (low >> 7);
                    delta = delta.wrapping_add(BinaryReader::i16_le(&[low as u8, high as u8]));
                    value = value.wrapping_add(delta);
                    out[i * channels + channel] = f32::from(value) / 32768.0;
                }
            }
        }
        Ok(out)
    }
}

fn block(
    bits: &mut BitReader<'_>,
    kind: Kind,
    degree: u32,
    channel: usize,
    coupled: bool,
) -> Result<Block> {
    let revolve = if coupled {
        bits.read_bits(if kind == Kind::Internal { 4 } else { 2 })?
    } else {
        0
    };
    let weight = bits.read_bits(32)?;
    let coefficient = bits.read_bits(16)?;
    Ok(Block {
        kind,
        degree,
        channel,
        weight,
        coefficient,
        revolve,
    })
}

fn dequantize(values: &[i32], degree: u32, weight: u32, coefficient: u32) -> Vec<f32> {
    let count = values.len();
    let mut frequency = [0usize; 7];
    let mut end = 0;
    for (i, offset) in [6, 6, 5, 4, 3, 2, 1].iter().enumerate() {
        let width = if degree >= *offset {
            1usize << (degree - offset)
        } else {
            0
        };
        frequency[i] = end + width / 2;
        end += width;
    }
    let mut ratios = [1.0; 7];
    for (i, ratio) in ratios.iter_mut().take(6).enumerate() {
        *ratio = 2f64.powf(-((weight >> (i * 5) & 31) as f64 - 15.0) * 0.5);
    }
    let mut weights = vec![1.0f32; count];
    weights[..frequency[0]].fill(ratios[0] as f32);
    let mut i = frequency[0];
    for j in 1..7 {
        let a = ratios[j - 1];
        let k = (ratios[j] - a) / (frequency[j] - frequency[j - 1]) as f64;
        while i < frequency[j] {
            weights[i] = (k * (i - frequency[j - 1]) as f64 + a) as f32;
            i += 1;
        }
    }
    for i in (15..count).step_by(16) {
        weights[i] *= ((weight >> 30) + 2) as f32 / 2.0;
    }
    weights[count - 1] = coefficient as f32;
    let scale = (2.0 / count as f64).sqrt() * f64::from(coefficient);
    values
        .iter()
        .zip(weights)
        .map(|(&v, w)| (scale * f64::from(1.0 / w) * f64::from(v)) as f32)
        .collect()
}
