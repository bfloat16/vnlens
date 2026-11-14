//! Stateful HCA spectral decoding, including HCA 3.0's resolution-zero noise,
//! delta intensity, extended HFR scales and changed HFR reflection direction.
//! Adapted from vgmstream clHCA (nyaga, kode54, bnnm and contributors); see
//! LICENSE.vgmstream. Header/frame semantics and PCM are checked against
//! CRI HCADecoder_DecodeHeader/SetFrameData/DecodeBlockFloat32.
mod tables;

use super::{audio::HcaHeader, corrupt};
use tables::*;
use vnlens_core::{Error, Result};
use vnlens_crypto::checksum::crc16::crc16_8005;
use vnlens_io::{BinaryIo, BitOrder, BitReader};

const BANDS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChannelType {
    Discrete,
    Primary,
    Secondary,
}

#[derive(Debug)]
struct Channel {
    kind: ChannelType,
    coded: usize,
    scales: [u8; BANDS],
    resolution: [u8; BANDS],
    intensity: [u8; 8],
    gain: [f32; BANDS],
    spectra: [f32; BANDS],
    previous: [f32; BANDS],
    noise: Vec<usize>,
    valid: Vec<usize>,
}

/// One independent HCA decoder. Each frame consumes exactly `block_size`
/// bytes and returns 1024 interleaved frames, including codec delay/padding.
/// The audio domain crops that framing once at the complete resource boundary.
#[derive(Debug)]
pub struct Decoder {
    header: HcaHeader,
    channels: Vec<Channel>,
    ath: [u8; BANDS],
    groups: usize,
    random: u32,
    frame: u32,
}

impl Decoder {
    pub fn new(header: HcaHeader) -> Result<Self> {
        if header.cipher == 56 {
            return Err(Error::UnknownScheme(Some(
                "HCA requires explicitly resolved CRIWARE key parameters".into(),
            )));
        }
        if header.cipher != 0 {
            return Err(Error::Unsupported(format!(
                "HCA cipher type {}",
                header.cipher
            )));
        }
        if !matches!(header.version, 0x101 | 0x102 | 0x103 | 0x200 | 0x300) {
            return Err(Error::Unsupported(format!(
                "HCA header version 0x{:04x}",
                header.version
            )));
        }
        let p = &header.compression;
        let total = usize::from(p.total_bands);
        let coded = usize::from(p.base_bands) + usize::from(p.stereo_bands);
        // 128 is the HCA transform size, not an application resource limit.
        if total == 0
            || total > BANDS
            || coded == 0
            || coded > total
            || p.min_resolution > p.max_resolution
            || p.max_resolution > 15
        {
            return Err(corrupt(
                24,
                "Invalid HCA transform bands or quantizer resolution",
            ));
        }
        let width = usize::from(p.bands_per_hfr_group);
        let groups = if width == 0 {
            0
        } else {
            (total - coded).div_ceil(width)
        };
        if coded + groups > BANDS {
            return Err(corrupt(24, "HCA scale factors exceed the transform layout"));
        }
        let count = usize::from(header.channels);
        let tracks = usize::from(p.track_count.max(1));
        if tracks > count {
            return Err(corrupt(32, "HCA track count exceeds its channels"));
        }
        let mut kinds = vec![ChannelType::Discrete; count];
        let per_track = count / tracks;
        if p.stereo_bands != 0 && per_track > 1 {
            for track in 0..tracks {
                let start = track * per_track;
                let pairs: &[usize] = match per_track {
                    2 | 3 => &[0],
                    4 if p.channel_config == 0 => &[0, 2],
                    4 => &[0],
                    5 if p.channel_config <= 2 => &[0, 3],
                    5 => &[0],
                    6 | 7 => &[0, 4],
                    8 => &[0, 4, 6],
                    _ => &[],
                };
                for &pair in pairs {
                    kinds[start + pair] = ChannelType::Primary;
                    kinds[start + pair + 1] = ChannelType::Secondary;
                }
            }
        }
        let channels = kinds
            .into_iter()
            .map(|kind| Channel {
                kind,
                coded: usize::from(p.base_bands)
                    + if kind == ChannelType::Secondary {
                        0
                    } else {
                        usize::from(p.stereo_bands)
                    },
                scales: [0; BANDS],
                resolution: [0; BANDS],
                intensity: [0; 8],
                gain: [0.; BANDS],
                spectra: [0.; BANDS],
                previous: [0.; BANDS],
                noise: Vec::new(),
                valid: Vec::new(),
            })
            .collect();
        let mut ath = [0; BANDS];
        match header.ath_type {
            0 => {}
            1 => {
                let mut accumulator = 0u64;
                for value in &mut ath {
                    accumulator += u64::from(header.sample_rate);
                    *value = ATH
                        .get((accumulator >> 13) as usize)
                        .copied()
                        .unwrap_or(255);
                }
            }
            kind => return Err(Error::Unsupported(format!("HCA ATH curve type {kind}"))),
        }
        Ok(Self {
            header,
            channels,
            ath,
            groups,
            random: 1,
            frame: 0,
        })
    }

    pub fn decode_frame(&mut self, block: &[u8]) -> Result<Vec<f32>> {
        let offset = u64::from(self.header.header_size)
            + u64::from(self.frame) * u64::from(self.header.block_size);
        if block.len() != usize::from(self.header.block_size) {
            return Err(
                BinaryIo::unexpected_eof("HCA decoder requires a complete encoded frame").into(),
            );
        }
        if crc16_8005(block) != 0 {
            return Err(corrupt(offset, "HCA block CRC-16 mismatch"));
        }
        let mut bits = BitReader::new(block, BitOrder::Msb);
        if bits.read_bits(16)? != 0xffff {
            return Err(corrupt(offset, "Invalid HCA frame sync"));
        }
        let noise = (bits.read_bits(9)? << 8).wrapping_sub(bits.read_bits(7)?);
        for channel in &mut self.channels {
            channel.unpack(&mut bits, self.groups, &self.header, offset)?;
            channel.resolve(noise, &self.ath, &self.header);
        }
        let count = self.channels.len();
        let mut output = vec![0.; 1024 * count];
        for subframe in 0..8 {
            for channel in &mut self.channels {
                channel.dequantize(&mut bits)?;
            }
            let hfr_channels = if self.header.compression.channel_config & 0x80 != 0 {
                1
            } else {
                count
            };
            for channel in &mut self.channels[..hfr_channels] {
                channel.restore(&self.header, self.groups, &mut self.random);
            }
            for index in 0..count.saturating_sub(1) {
                let (left, right) = self.channels.split_at_mut(index + 1);
                let left = &mut left[index];
                let right = &mut right[0];
                if left.kind != ChannelType::Primary {
                    continue;
                }
                let p = &self.header.compression;
                let ratio_l = INTENSITY[usize::from(right.intensity[subframe])];
                let ratio_r = 2. - ratio_l;
                for band in usize::from(p.base_bands)..usize::from(p.total_bands) {
                    right.spectra[band] = left.spectra[band] * ratio_r;
                    left.spectra[band] *= ratio_l;
                }
                if p.ms_stereo != 0 {
                    for band in 0..usize::from(p.base_bands) {
                        let (l, r) = (left.spectra[band], right.spectra[band]);
                        left.spectra[band] = (l + r) * std::f32::consts::FRAC_1_SQRT_2;
                        right.spectra[band] = (l - r) * std::f32::consts::FRAC_1_SQRT_2;
                    }
                }
            }
            for (index, channel) in self.channels.iter_mut().enumerate() {
                let wave = channel.transform();
                for (sample, value) in wave.into_iter().enumerate() {
                    output[(subframe * BANDS + sample) * count + index] = value;
                }
            }
        }
        self.frame = self
            .frame
            .checked_add(1)
            .ok_or_else(|| corrupt(offset, "HCA encoded frame count overflow"))?;
        Ok(output)
    }
}

impl Channel {
    fn unpack(
        &mut self,
        bits: &mut BitReader<'_>,
        groups: usize,
        header: &HcaHeader,
        offset: u64,
    ) -> Result<()> {
        let modern = header.version > 0x200;
        let extra = if modern && self.kind != ChannelType::Secondary {
            groups
        } else {
            0
        };
        let count = self.coded + extra;
        let delta_bits = bits.read_bits(3)? as u8;
        if delta_bits >= 6 {
            for value in &mut self.scales[..count] {
                *value = bits.read_bits(6)? as u8;
            }
        } else if delta_bits != 0 {
            let escape = (1i32 << delta_bits) - 1;
            let mut value = bits.read_bits(6)? as i32;
            self.scales[0] = value as u8;
            for scale in self.scales.iter_mut().take(count).skip(1) {
                let delta = bits.read_bits(delta_bits)? as i32;
                value = if delta == escape {
                    bits.read_bits(6)? as i32
                } else {
                    value + delta - (escape >> 1)
                };
                // Modern SDK decoders wrap differential six-bit scales.
                if modern {
                    value &= 63;
                }
                if !(0..64).contains(&value) {
                    return Err(corrupt(offset, "Invalid HCA differential scale factor"));
                }
                *scale = value as u8;
            }
        } else {
            self.scales.fill(0);
        }
        for index in (0..extra).rev() {
            self.scales[BANDS - extra + index] = self.scales[self.coded + index];
        }
        if self.kind == ChannelType::Secondary {
            let mut value = bits.peek_bits(4)? as i32;
            if value < 15 {
                bits.read_bits(4)?;
                self.intensity[0] = value as u8;
                let delta = if modern { bits.read_bits(2)? as u8 } else { 3 };
                let width = delta + 1;
                let escape = (1i32 << width) - 1;
                for intensity in &mut self.intensity[1..] {
                    let code = bits.read_bits(width)? as i32;
                    value = if delta == 3 {
                        code
                    } else if code == escape {
                        bits.read_bits(4)? as i32
                    } else {
                        value - (escape >> 1) + code
                    };
                    if !(0..16).contains(&value) {
                        return Err(corrupt(offset, "Invalid HCA differential stereo intensity"));
                    }
                    *intensity = value as u8;
                }
            } else if modern {
                bits.read_bits(4)?;
                self.intensity.fill(7);
            } else {
                self.intensity[0] = 15;
            }
        } else if !modern {
            for scale in &mut self.scales[BANDS - groups..] {
                *scale = bits.read_bits(6)? as u8;
            }
        }
        Ok(())
    }

    fn resolve(&mut self, noise: u32, ath: &[u8; BANDS], header: &HcaHeader) {
        self.noise.clear();
        self.valid.clear();
        for (i, &threshold) in ath.iter().enumerate().take(self.coded) {
            let scale = self.scales[i];
            let resolution = if scale == 0 {
                0
            } else {
                let curve = i32::from(threshold) + (noise.wrapping_add(i as u32) >> 8) as i32 + 1
                    - ((5 * i32::from(scale)) >> 1);
                let value = if curve < 0 {
                    15
                } else {
                    INVERT.get(curve as usize).copied().unwrap_or(0)
                };
                let p = &header.compression;
                let value = value.clamp(p.min_resolution, p.max_resolution);
                if value == 0 {
                    self.noise.push(i);
                } else {
                    self.valid.push(i);
                }
                value
            };
            self.resolution[i] = resolution;
            self.gain[i] = SCALE[usize::from(scale)] * RANGE[usize::from(resolution)];
        }
    }

    fn dequantize(&mut self, bits: &mut BitReader<'_>) -> Result<()> {
        for i in 0..self.coded {
            let resolution = usize::from(self.resolution[i]);
            let width = MAX_BITS[resolution];
            let code = bits.peek_bits(width)?;
            let value = if resolution > 7 {
                let value = (1 - ((code & 1) as i32 * 2)) * (code >> 1) as i32;
                bits.read_bits(width - u8::from(value == 0))?;
                value as f32
            } else {
                let index = (resolution << 4) + code as usize;
                bits.read_bits(CODE_BITS[index])?;
                CODE_VALUE[index]
            };
            self.spectra[i] = self.gain[i] * value;
        }
        self.spectra[self.coded..].fill(0.);
        Ok(())
    }

    fn restore(&mut self, header: &HcaHeader, groups: usize, random: &mut u32) {
        let p = &header.compression;
        if p.min_resolution == 0
            && !self.valid.is_empty()
            && (p.ms_stereo == 0 || self.kind == ChannelType::Primary)
        {
            for &target in &self.noise {
                *random = random.wrapping_mul(0x343fd).wrapping_add(0x269ec3);
                let select = (((*random >> 16) & 0x7fff) as usize * self.valid.len()) >> 15;
                let source = self.valid[self.valid.len() - 1 - select];
                let scale = (i32::from(self.scales[target]) - i32::from(self.scales[source]) + 62)
                    .max(0) as usize;
                self.spectra[target] = CONVERSION[scale] * self.spectra[source];
            }
        }
        if p.bands_per_hfr_group == 0 || self.kind == ChannelType::Secondary {
            return;
        }
        let mut high = usize::from(p.base_bands) + usize::from(p.stereo_bands);
        let mut low = high as isize - 1;
        let limit = if header.version <= 0x200 {
            groups
        } else {
            groups / 2
        };
        for group in 0..groups {
            for _ in 0..p.bands_per_hfr_group {
                if high >= usize::from(p.total_bands) || !(0..BANDS as isize).contains(&low) {
                    break;
                }
                let scale = (i32::from(self.scales[BANDS - groups + group])
                    - i32::from(self.scales[low as usize])
                    + 63)
                    .max(0) as usize;
                self.spectra[high] = CONVERSION[scale] * self.spectra[low as usize];
                high += 1;
                low += if group < limit { -1 } else { 1 };
            }
        }
        self.spectra[high - 1] = 0.;
    }

    fn transform(&mut self) -> [f32; BANDS] {
        let mut input = self.spectra;
        let mut output = [0.; BANDS];
        let mut width = 64;
        for _ in 0..7 {
            for group in 0..BANDS / (width * 2) {
                let base = group * width * 2;
                for k in 0..width {
                    let a = input[base + k * 2];
                    let b = input[base + k * 2 + 1];
                    output[base + k] = a + b;
                    output[base + width + k] = a - b;
                }
            }
            std::mem::swap(&mut input, &mut output);
            width /= 2;
        }
        width = 1;
        for stage in 0..7 {
            for group in 0..BANDS / (width * 2) {
                let base = group * width * 2;
                for k in 0..width {
                    let (a, b) = (input[base + k], input[base + width + k]);
                    let (sin, cos) = (SIN[stage][group * width + k], COS[stage][group * width + k]);
                    output[base + k] = a * sin - b * cos;
                    output[base + width * 2 - 1 - k] = a * cos + b * sin;
                }
            }
            std::mem::swap(&mut input, &mut output);
            width *= 2;
        }
        for i in 0..64 {
            output[i] = WINDOW[i] * input[i + 64] + self.previous[i];
            output[i + 64] = WINDOW[i + 64] * input[127 - i] - self.previous[i + 64];
            self.previous[i] = WINDOW[127 - i] * input[63 - i];
            self.previous[i + 64] = WINDOW[63 - i] * input[i];
        }
        output
    }
}

#[cfg(test)]
#[path = "../../../tests/criware/hca/mod.rs"]
mod tests;
