//! ERI/MEI version-0x28 lossy frames, verified against SGLImageDecoder
//! sub_5EA880, sub_5EB520, sub_5EB1F0 and sub_5EC970. Quantized bytes are
//! interleaved by coefficient within each blockset. Motion vectors first
//! integrate vertically, then horizontally, with half-pixel sampling.
use super::{ImageInfo, bad};
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{Error, Result};
use vnlens_crypto::compress::erisa::{ErinaDecoder, GammaDecoder, HuffmanTree, integer};
use vnlens_io::{BitOrder, BitReader};

pub(super) fn decode(
    info: &ImageInfo,
    payload: &[u8],
    previous: Option<&[u8]>,
    following: Option<&[u8]>,
    cancel: &AtomicBool,
) -> Result<Vec<u8>> {
    if !matches!(info.transformation, 1 | 5) || !matches!(info.sampling, 0x40404 | 0x40101) {
        return Err(Error::Unsupported(
            "ERISA lossy transformation/sampling".into(),
        ));
    }
    let width = info.width as usize;
    let height = info.height as usize;
    let channels = if info.format & 0x0400_0000 != 0 {
        4
    } else if info.bpp <= 8 {
        1
    } else {
        3
    };
    let mut bits = BitReader::new(payload, BitOrder::Msb);
    let version = bits.read_bits(8)?;
    let flags = bits.read_bits(8)?;
    let encoding = bits.read_bits(8)?;
    bits.read_bits(8)?;
    if version != 0x28 {
        return Err(Error::Unsupported(format!(
            "ERISA lossy frame version {version}"
        )));
    }
    let lot = info.transformation == 5 && encoding != 1;
    let columns = width.div_ceil(16) + usize::from(lot);
    let rows = height.div_ceil(16) + usize::from(lot);
    let block_count = columns
        .checked_mul(rows)
        .ok_or_else(|| bad(0, "ERISA lossy block count overflow"))?;
    let subsampled = info.sampling == 0x40101;
    let planes = if channels == 1 {
        4
    } else if subsampled {
        6 + if channels == 4 { 4 } else { 0 }
    } else {
        channels * 4
    };
    if bits.read_bit()? != 0 {
        return Err(bad(4, "Invalid ERISA lossy separator"));
    }
    let mut tree = HuffmanTree::default();
    let mut quantizers = [0u32; 128];
    for value in &mut quantizers {
        *value = tree.decode(&mut bits, false, true)? + 1;
    }
    let mut gamma = GammaDecoder::default();
    gamma.reset(&mut bits)?;
    let mut scales = vec![
        0;
        block_count
            .checked_mul(2)
            .ok_or_else(|| bad(0, "ERISA scale count overflow"))?
    ];
    gamma.decode(&mut bits, &mut scales, Some(cancel))?;
    let motion_columns = width.div_ceil(16);
    let motion_count = motion_columns
        .checked_mul(height.div_ceil(16))
        .ok_or_else(|| bad(0, "ERISA motion count overflow"))?;
    let mut motion_flags = vec![u8::from(previous.is_some()); motion_count];
    let mut vectors = vec![
        0;
        motion_count
            .checked_mul(4)
            .ok_or_else(|| bad(0, "ERISA motion vector count overflow"))?
    ];
    if flags & 1 != 0 {
        gamma.reset(&mut bits)?;
        gamma.decode(&mut bits, &mut motion_flags, Some(cancel))?;
        gamma.reset(&mut bits)?;
        gamma.decode(&mut bits, &mut vectors, Some(cancel))?;
    }
    for i in motion_columns..motion_count {
        for j in 0..4 {
            vectors[i * 4 + j] =
                vectors[i * 4 + j].wrapping_add(vectors[(i - motion_columns) * 4 + j]);
        }
    }
    for row in vectors.chunks_mut(motion_columns * 4) {
        for i in 1..row.len() / 4 {
            for j in 0..4 {
                row[i * 4 + j] = row[i * 4 + j].wrapping_add(row[(i - 1) * 4 + j]);
            }
        }
    }
    let padded_width = columns
        .checked_mul(16)
        .ok_or_else(|| bad(0, "ERISA padded width overflow"))?;
    let padded_height = rows
        .checked_mul(16)
        .ok_or_else(|| bad(0, "ERISA padded height overflow"))?;
    let plane_size = padded_width
        .checked_mul(padded_height)
        .ok_or_else(|| bad(0, "ERISA plane size overflow"))?;
    let mut samples = vec![vec![0i16; plane_size]; channels];
    let mut vertical = vec![[0i16; 64]; columns * channels * 2];
    let zigzag = zigzag();
    let mut entropy = ErinaDecoder::new(true);
    let mut encoded = vec![
        0u8;
        columns
            .checked_mul(planes * 64)
            .ok_or_else(|| bad(0, "ERISA coefficient row overflow"))?
    ];
    for by in 0..rows {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let mut horizontal = vec![[0i16; 64]; channels * 2];
        entropy.decode(&mut bits, &mut encoded, Some(cancel))?;
        for bx in 0..columns {
            let mut blocks = vec![[0i16; 64]; planes];
            for k in 0..planes {
                for i in 0..64 {
                    blocks[k][i] = i16::from(encoded[bx * planes * 64 + i * planes + k] as i8);
                }
            }
            if !lot {
                let y = blocks[0][0] as i8;
                for block in blocks.iter_mut().take(4).skip(1) {
                    block[0] = i16::from((block[0] as i8).wrapping_add(y));
                }
                let first = if subsampled { 6 } else { 4 };
                for start in (first..planes).step_by(4) {
                    let base = blocks[start][0] as i8;
                    for block in blocks.iter_mut().skip(start + 1).take(3) {
                        block[0] = i16::from((block[0] as i8).wrapping_add(base));
                    }
                }
            }
            for (k, block) in blocks.iter_mut().enumerate() {
                let (channel, quadrant) = if k < 4 {
                    (0, k)
                } else if subsampled && k < 6 {
                    (k - 3, 0)
                } else {
                    let start = if subsampled { 6 } else { 4 };
                    let channel = if subsampled { 3 } else { 1 + (k - start) / 4 };
                    (channel, (k - start) % 4)
                };
                let quant = if channel == 1 || channel == 2 { 1 } else { 0 };
                let scale = scales[(by * columns + bx) * 2 + quant] as i8;
                let parity = u32::from((scale as u8) & 1);
                let power = i32::from(scale) >> 1;
                let shift = if power < 0 {
                    (parity as i32 - power) as u32
                } else {
                    parity
                };
                let mut arranged = [0i16; 64];
                for i in 0..64 {
                    let factor = quantizers[quant * 64 + i] * if parity != 0 { 3 } else { 1 };
                    let factor = (factor.wrapping_shl(power.max(0) as u32) as u16) as i16;
                    let product = block[i].wrapping_mul(factor);
                    arranged[zigzag[i]] = if shift >= 16 {
                        product >> 15
                    } else {
                        product >> shift
                    };
                }
                *block = arranged;
                if lot {
                    let group = channel * 2
                        + if subsampled && (channel == 1 || channel == 2) {
                            0
                        } else {
                            quadrant / 2
                        };
                    let vertical_slot = bx * channels * 2 + channel * 2 + quadrant % 2;
                    integer::ilot(block, &mut horizontal[group], &mut vertical[vertical_slot]);
                } else {
                    integer::idct(block);
                }
                let repeat = if subsampled && (channel == 1 || channel == 2) {
                    2
                } else {
                    1
                };
                let origin_x = (bx * 16 + (quadrant % 2) * 8) as i64
                    - if lot {
                        if repeat == 2 { 16 } else { 8 }
                    } else {
                        0
                    };
                let origin_y = (by * 16 + (quadrant / 2) * 8) as i64
                    - if lot {
                        if repeat == 2 { 16 } else { 8 }
                    } else {
                        0
                    };
                for y in 0..8 * repeat {
                    for x in 0..8 * repeat {
                        let dx = origin_x + x as i64;
                        let dy = origin_y + y as i64;
                        if dx < 0
                            || dy < 0
                            || dx >= padded_width as i64
                            || dy >= padded_height as i64
                        {
                            continue;
                        }
                        let value = block[(y / repeat) * 8 + x / repeat];
                        samples[channel][dy as usize * padded_width + dx as usize] =
                            if channel == 1 || channel == 2 || previous.is_some() {
                                value.clamp(-128, 127)
                            } else {
                                value.clamp(0, 255)
                            };
                    }
                }
            }
        }
    }
    let mut out = vec![
        0;
        width
            .checked_mul(height)
            .and_then(|v| v.checked_mul(4))
            .ok_or_else(|| bad(0, "ERISA output buffer overflow"))?
    ];
    for y in 0..height {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        for x in 0..width {
            let at = y * padded_width + x;
            let dst_y = if info.top_down { y } else { height - 1 - y };
            let dst = (dst_y * width + x) * 4;
            let yy = i32::from(samples[0][at]) * if previous.is_some() { 2 } else { 1 };
            let u = if channels >= 3 {
                i32::from(samples[1][at]) * if previous.is_some() { 2 } else { 1 }
            } else {
                0
            };
            let v = if channels >= 3 {
                i32::from(samples[2][at]) * if previous.is_some() { 2 } else { 1 }
            } else {
                0
            };
            let mut values = [
                yy + ((7 * u) >> 2),
                yy - ((3 * u + 6 * v) >> 3),
                yy + ((3 * v) >> 1),
                if channels == 4 {
                    i32::from(samples[3][at]) * if previous.is_some() { 2 } else { 1 }
                } else {
                    255
                },
            ];
            if info.format & 0xffff == 3 {
                values.swap(0, 2);
            }
            if previous.is_some() || following.is_some() {
                let index = y / 16 * motion_columns + x / 16;
                let flag = motion_flags[index] as i8;
                for (channel, value) in values.iter_mut().enumerate() {
                    let before = if flag == 1 || flag == 2 {
                        Some(sample(
                            previous
                                .ok_or_else(|| bad(0, "ERISA frame needs a preceding reference"))?,
                            info,
                            x,
                            y,
                            channel,
                            vectors[index * 4] as i8,
                            vectors[index * 4 + 1] as i8,
                        )?)
                    } else {
                        None
                    };
                    let after = if flag == -1 || flag == 2 {
                        Some(sample(
                            following
                                .ok_or_else(|| bad(0, "ERISA frame needs a following reference"))?,
                            info,
                            x,
                            y,
                            channel,
                            vectors[index * 4 + 2] as i8,
                            vectors[index * 4 + 3] as i8,
                        )?)
                    } else {
                        None
                    };
                    *value += match (before, after) {
                        (Some(a), Some(b)) => average(a, b),
                        (Some(a), _) | (_, Some(a)) => a,
                        _ => 0,
                    };
                }
            }
            for channel in 0..4 {
                out[dst + channel] = values[channel].clamp(0, 255) as u8;
            }
        }
    }
    Ok(out)
}

fn zigzag() -> [usize; 64] {
    let mut result = [0; 64];
    let mut index = 0;
    for diagonal in 0usize..15 {
        let start = diagonal.saturating_sub(7);
        let end = diagonal.min(7);
        if diagonal % 2 == 0 {
            for x in start..=end {
                result[index] = x + (diagonal - x) * 8;
                index += 1;
            }
        } else {
            for y in start..=end {
                result[index] = diagonal - y + y * 8;
                index += 1;
            }
        }
    }
    result
}

fn average(a: i32, b: i32) -> i32 {
    (a + b + 1) / 2
}
fn sample(
    reference: &[u8],
    info: &ImageInfo,
    x: usize,
    y: usize,
    channel: usize,
    vx: i8,
    vy: i8,
) -> Result<i32> {
    let width = info.width as usize;
    let height = info.height as usize;
    let base_x = x / 16 * 16;
    let base_y = y / 16 * 16;
    let mx = base_x as i32 + (i32::from(vx) >> 1);
    let my = base_y as i32 + (i32::from(vy) >> 1);
    let (mx, my) = if mx < 0 || my < 0 || mx as usize + 16 > width || my as usize + 16 > height {
        (base_x, base_y)
    } else {
        (mx as usize, my as usize)
    };
    let pixel = |sx: usize, sy: usize| -> Result<i32> {
        let px = (mx + x % 16 + sx).min(width - 1);
        let py = (my + y % 16 + sy).min(height - 1);
        let py = if info.top_down { py } else { height - 1 - py };
        reference
            .get((py * width + px) * 4 + channel)
            .copied()
            .map(i32::from)
            .ok_or_else(|| bad(0, "ERISA reference dimensions differ"))
    };
    let row = |sy| -> Result<i32> {
        let a = pixel(0, sy)?;
        if vx & 1 != 0 {
            Ok(average(a, pixel(1, sy)?))
        } else {
            Ok(a)
        }
    };
    let a = row(0)?;
    if vy & 1 != 0 {
        Ok(average(a, row(1)?))
    } else {
        Ok(a)
    }
}
