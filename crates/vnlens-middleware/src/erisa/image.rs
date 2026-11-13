//! ERI lossless block decoding. Native plane order is B,G,R,A. Arrangement
//! and color operations precede horizontal and vertical modulo-256 prediction.
//! Based on ERISADecoder and GARbro EriReader::DecodeLosslessImage (MIT).
use super::{ImageInfo, bad};
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{Error, Result};
use vnlens_crypto::compress::erisa::{ErinaDecoder, GammaDecoder, HuffmanTree, ProbabilityDecoder};
use vnlens_io::{BitOrder, BitReader};

pub(super) fn decode_frame(
    info: &ImageInfo,
    payload: &[u8],
    palette: Option<&[u8]>,
    previous: Option<&[u8]>,
    next: Option<&[u8]>,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    let result = decode_inner(info, payload, palette, previous, next, cancelled);
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    match result {
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData => Err(bad(
            0,
            &format!("ERISA image entropy decoding failed: {error}"),
        )),
        result => result,
    }
}
fn decode_inner(
    info: &ImageInfo,
    payload: &[u8],
    palette: Option<&[u8]>,
    previous: Option<&[u8]>,
    next: Option<&[u8]>,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    if info.transformation != 0x0302_0000 {
        return super::lossy::decode(info, payload, previous, next, cancelled);
    }
    let channels = match (info.format & 0xffff, info.bpp) {
        (1 | 3, 8) | (2, 8) => 1,
        (1 | 3, 16 | 24 | 32) => {
            if info.format & 0x0400_0000 != 0 {
                4
            } else {
                3
            }
        }
        _ => return Err(Error::Unsupported("ERISA pixel format".into())),
    };
    let block = 1usize
        .checked_shl(info.blocking_degree)
        .ok_or_else(|| bad(0, "ERISA block degree exceeds address space"))?;
    let area = block
        .checked_mul(block)
        .ok_or_else(|| bad(0, "ERISA block area overflow"))?;
    let samples = area
        .checked_mul(channels)
        .ok_or_else(|| bad(0, "ERISA block samples overflow"))?;
    let width = usize::try_from(info.width).map_err(std::io::Error::other)?;
    let height = usize::try_from(info.height).map_err(std::io::Error::other)?;
    let size = width
        .checked_mul(height)
        .and_then(|v| v.checked_mul(4))
        .ok_or_else(|| bad(0, "ERISA pixel buffer overflow"))?;
    let columns = width.div_ceil(block);
    let rows = height.div_ceil(block);
    let mut out = allocate(size)?;
    let mut arranged = allocate(samples)?;
    let mut decoded = allocate(samples)?;
    let mut left = allocate(
        block
            .checked_mul(channels)
            .ok_or_else(|| bad(0, "ERISA column buffer overflow"))?,
    )?;
    let mut above = allocate(
        columns
            .checked_mul(left.len())
            .ok_or_else(|| bad(0, "ERISA line buffer overflow"))?,
    )?;
    let mut bits = BitReader::new(payload, BitOrder::Msb);
    let version = bits.read_bits(8)?;
    let table = bits.read_bits(8)?;
    let encoding = bits.read_bits(8)?;
    let bit_count = bits.read_bits(8)?;
    if table != 0 || encoding & !1 != 0 || !matches!((version, bit_count), (1, 0) | (8 | 16, 8)) {
        return Err(Error::Unsupported(format!(
            "ERISA lossless frame version {version}, table {table}, encoding {encoding}, bits {bit_count}"
        )));
    }
    let mut operation_tree = HuffmanTree::default();
    let mut operations = Vec::new();
    if encoding != 0 && channels >= 3 {
        for _ in 0..columns
            .checked_mul(rows)
            .ok_or_else(|| bad(0, "ERISA operation count overflow"))?
        {
            operations.push(operation(info, &mut bits, &mut operation_tree)?);
        }
    }
    if bits.read_bit()? != 0 {
        return Err(bad(4, "Invalid ERISA lossless separator bit"));
    }
    let mut entropy = match info.architecture {
        -1 => {
            let mut gamma = GammaDecoder::default();
            if encoding != 0 {
                gamma.reset(&mut bits)?;
            }
            Entropy::Gamma(&mut bits, gamma)
        }
        -4 => Entropy::Huffman(&mut bits, ErinaDecoder::new(false), operation_tree),
        -16 => Entropy::Probability(Box::new(ProbabilityDecoder::new(&mut bits)?)),
        value => return Err(Error::Unsupported(format!("ERISA architecture {value}"))),
    };
    for by in 0..rows {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        left.fill(0);
        for bx in 0..columns {
            let op = if channels >= 3 {
                if encoding != 0 {
                    operations[by * columns + bx]
                } else {
                    entropy.operation()?
                }
            } else if info.format & 0xffff == 2 {
                0xc0
            } else {
                0
            };
            entropy.decode(&mut arranged, encoding == 0, cancelled)?;
            let arrangement = (op >> 4) & 3;
            for (i, &byte) in arranged.iter().enumerate() {
                let dest = match arrangement {
                    0 => i,
                    1 => (i / area) * area + (i % block) * block + (i % area) / block,
                    2 => (i % channels) * area + i / channels,
                    _ => {
                        (i % channels) * area
                            + ((i / channels) % block) * block
                            + i / (channels * block)
                    }
                };
                decoded[dest] = byte;
            }
            if op != 0 {
                let color = op & 15;
                let base_channel = (color >> 2).wrapping_sub(1) as usize;
                if color & 3 != 0 && base_channel < 3 && color >= 5 {
                    for i in 0..area {
                        let base = decoded[base_channel * area + i];
                        let targets: &[usize] = match color {
                            5 => &[1],
                            6 => &[2],
                            7 => &[1, 2],
                            9 => &[0],
                            10 => &[2],
                            11 => &[0, 2],
                            13 => &[0],
                            14 => &[1],
                            15 => &[0, 1],
                            _ => &[],
                        };
                        for &target in targets {
                            decoded[target * area + i] =
                                decoded[target * area + i].wrapping_add(base);
                        }
                    }
                }
                for (line, last) in left.iter_mut().enumerate() {
                    let line_start = line * block;
                    if op & 0x40 != 0 {
                        for byte in &mut decoded[line_start..line_start + block] {
                            *last = last.wrapping_add(*byte);
                            *byte = *last;
                        }
                    } else {
                        *last = decoded[line_start + block - 1];
                    }
                }
                for channel in 0..channels {
                    let line = bx * block * channels + channel * block;
                    for y in 0..block {
                        for x in 0..block {
                            let at = channel * area + y * block + x;
                            let prior = if y == 0 {
                                above[line + x]
                            } else {
                                decoded[at - block]
                            };
                            decoded[at] = decoded[at].wrapping_add(prior);
                        }
                    }
                    above[line..line + block].copy_from_slice(
                        &decoded[channel * area + area - block..channel * area + area],
                    );
                }
            }
            for y in 0..block.min(height - by * block) {
                let sy = by * block + y;
                let dy = if info.top_down { sy } else { height - 1 - sy };
                for x in 0..block.min(width - bx * block) {
                    let src = y * block + x;
                    let dst = (dy * width + bx * block + x) * 4;
                    if channels >= 3 {
                        let reverse = info.format & 0xffff == 3;
                        out[dst] = decoded[if reverse { 2 * area + src } else { src }];
                        out[dst + 1] = decoded[area + src];
                        out[dst + 2] = decoded[if reverse { src } else { 2 * area + src }];
                        if info.bpp == 16 {
                            for byte in &mut out[dst..dst + 3] {
                                let value = *byte >> 3;
                                *byte = (value << 3) | (value >> 2);
                            }
                        }
                        out[dst + 3] = if channels == 4 {
                            decoded[3 * area + src]
                        } else {
                            255
                        };
                    } else if let Some(palette) = palette {
                        let color = usize::from(decoded[src]) * 4;
                        let value = palette
                            .get(color..color + 4)
                            .ok_or_else(|| bad(0, "ERISA palette index exceeds palette"))?;
                        out[dst..dst + 4].copy_from_slice(value);
                        out[dst + 3] = 255;
                    } else {
                        out[dst..dst + 3].fill(decoded[src]);
                        out[dst + 3] = 255;
                    }
                    if let Some(previous) = previous {
                        let old = previous
                            .get(dst..dst + 4)
                            .ok_or_else(|| bad(0, "ERISA reference image dimensions differ"))?;
                        for ch in 0..if channels == 4 { 4 } else { 3 } {
                            out[dst + ch] = out[dst + ch].wrapping_add(old[ch]);
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

fn operation(info: &ImageInfo, bits: &mut BitReader<'_>, tree: &mut HuffmanTree) -> Result<u32> {
    match info.architecture {
        -1 => Ok(bits.read_bits(4)? | 0xc0),
        -4 => Ok(tree.decode(bits, false, false)?),
        value => Err(Error::Unsupported(format!(
            "ERISA operation architecture {value}"
        ))),
    }
}

fn allocate(size: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(size).map_err(std::io::Error::other)?;
    out.resize(size, 0);
    Ok(out)
}

enum Entropy<'a, 'b> {
    Gamma(&'a mut BitReader<'b>, GammaDecoder),
    Huffman(&'a mut BitReader<'b>, ErinaDecoder, HuffmanTree),
    Probability(Box<ProbabilityDecoder<'a, 'b>>),
}
impl Entropy<'_, '_> {
    fn operation(&mut self) -> Result<u32> {
        match self {
            Self::Gamma(bits, _) => Ok(bits.read_bits(4)? | 0xc0),
            Self::Huffman(bits, _, tree) => Ok(tree.decode(bits, false, false)?),
            Self::Probability(decoder) => Ok(decoder.operation()?),
        }
    }
    fn decode(&mut self, out: &mut [u8], reset: bool, cancel: &AtomicBool) -> Result<()> {
        match self {
            Self::Gamma(bits, decoder) => {
                if reset {
                    decoder.reset(bits)?;
                }
                decoder.decode(bits, out, Some(cancel))?;
            }
            Self::Huffman(bits, decoder, _) => decoder.decode(bits, out, Some(cancel))?,
            Self::Probability(decoder) => decoder.decode(out, Some(cancel))?,
        }
        Ok(())
    }
}
