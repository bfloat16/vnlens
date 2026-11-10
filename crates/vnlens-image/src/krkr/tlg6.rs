//! TLG6.0 raw: LE dimensions, three zero method flags, trained slide-coded
//! 8x8 filter map and per-channel Golomb streams. LoadTLG.cpp's serpentine
//! block ordering, sixteen inverse color filters and MED/AVG predictors are
//! applied to byte residuals. See also tlg-rs tlg6/decode.rs (MIT, XuanRikka).
use super::{Image, ImageMeta, OffsetUnit, PixelBuffer, corrupt};
use vnlens_core::{Error, Result};
use vnlens_crypto::compress::{tlg::Slide, tlg6};
use vnlens_io::BinaryReader;
pub(super) const MAGIC: &[u8; 11] = b"TLG6.0\0raw\x1a";

pub(super) fn header(raw: &[u8], x: i32, y: i32) -> Result<(ImageMeta, u32)> {
    let mut r = BinaryReader::new(raw);
    if r.read_bytes(11)? != MAGIC {
        return Err(Error::InvalidFormat);
    }
    let colors = r.read_u8()?;
    if !matches!(colors, 1 | 3 | 4) {
        return Err(Error::Unsupported("TLG6 color count".into()));
    }
    if r.read_bytes(3)? != [0, 0, 0] {
        return Err(Error::Unsupported("TLG6 method flags".into()));
    }
    let width = r.read_u32_le()?;
    let height = r.read_u32_le()?;
    let bits = r.read_u32_le()?;
    if width == 0 || height == 0 {
        return Err(corrupt("Zero TLG6 dimensions"));
    }
    let meta = ImageMeta {
        width,
        height,
        offset_x: x,
        offset_y: y,
        offset_unit: OffsetUnit::Pixels,
        bpp: u16::from(colors) * 8,
    };
    meta.rgba_size()?;
    Ok((meta, bits))
}

pub(super) fn decode(raw: &[u8], x: i32, y: i32) -> Result<Image> {
    let (meta, max_bits) = header(raw, x, y)?;
    let width = meta.width as usize;
    let height = meta.height as usize;
    let colors = usize::from(meta.bpp / 8);
    let blocks = width.div_ceil(8);
    let filter_count = blocks
        .checked_mul(height.div_ceil(8))
        .ok_or_else(|| corrupt("TLG6 filter count overflow"))?;
    let mut r = BinaryReader::new_at(raw, 27)?;
    let stored = r.read_u32_le()? as usize;
    let mut dictionary = [0; 4096];
    for (index, pair) in dictionary.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        pair[..4].fill((index / 16) as u8);
        pair[4..].fill((index % 16) as u8);
    }
    let filters = Slide::with_dictionary(dictionary).decode(r.read_bytes(stored)?, filter_count)?;
    if filters.iter().any(|&f| f > 31) {
        return Err(corrupt("Invalid TLG6 color filter"));
    }
    let mut pixels = vec![0; meta.rgba_size()?];
    let zero: [u8; 4] = [0, 0, 0, if colors == 3 { 255 } else { 0 }];
    for y0 in (0..height).step_by(8) {
        let rows = (height - y0).min(8);
        let count = width * rows;
        let mut residuals = vec![[0u8; 4]; count];
        for channel in 0..colors {
            let field = r.read_u32_le()?;
            if field >> 30 != 0 {
                return Err(Error::Unsupported("TLG6 entropy coding method".into()));
            }
            let bits = field & 0x3fff_ffff;
            if bits > max_bits {
                return Err(corrupt("TLG6 stream exceeds declared maximum bit length"));
            }
            let data = r.read_bytes(bits.div_ceil(8) as usize)?;
            let values = tlg6::decode(data, bits, count)?;
            for (pixel, value) in residuals.iter_mut().zip(values) {
                pixel[channel] = value;
            }
        }
        for row in 0..rows {
            let y = y0 + row;
            let mut left = zero;
            let mut upper_left = zero;
            for block in 0..blocks {
                let block_width = (width - block * 8).min(8);
                let source_row = if block % 2 == 0 { row } else { rows - row - 1 };
                let source = block * 8 * rows + source_row * block_width;
                let filter = filters[y0 / 8 * blocks + block];
                for column in 0..block_width {
                    let input = source
                        + if y % 2 == 0 {
                            column
                        } else {
                            block_width - column - 1
                        };
                    let residual = inverse(filter >> 1, residuals[input]);
                    let x = block * 8 + column;
                    let at = (y * width + x) * 4;
                    let mut above = zero;
                    if y != 0 {
                        above.copy_from_slice(&pixels[at - width * 4..at - width * 4 + 4]);
                    }
                    for c in 0..4 {
                        let prediction = if filter & 1 != 0 {
                            (u16::from(left[c]) + u16::from(above[c])).div_ceil(2) as u8
                        } else {
                            let low = left[c].min(above[c]);
                            let high = left[c].max(above[c]);
                            if upper_left[c] >= high {
                                low
                            } else if upper_left[c] < low {
                                high
                            } else {
                                left[c].wrapping_add(above[c]).wrapping_sub(upper_left[c])
                            }
                        };
                        left[c] = prediction.wrapping_add(residual[c]);
                        pixels[at + c] = left[c];
                    }
                    upper_left = above;
                }
            }
        }
    }
    if r.remaining() != 0 {
        return Err(corrupt("Trailing TLG6 pixel data"));
    }
    if colors == 1 {
        for pixel in pixels.as_chunks_mut::<4>().0 {
            *pixel = [pixel[0], pixel[0], pixel[0], 255];
        }
    }
    Ok(Image {
        meta,
        pixels: PixelBuffer::Bgra8(pixels),
    })
}

fn inverse(filter: u8, pixel: [u8; 4]) -> [u8; 4] {
    let [b, g, r, a] = pixel.map(u16::from);
    let (b, g, r) = match filter {
        0 => (b, g, r),
        1 => (b + g, g, r + g),
        2 => (b, g + b, r + b + g),
        3 => (b + r + g, g + r, r),
        4 => (b + r, g + b + r, r + b + r + g),
        5 => (b + r, g + b + r, r),
        6 => (b + g, g, r),
        7 => (b, g + b, r),
        8 => (b, g, r + g),
        9 => (b + g + r + b, g + r + b, r + b),
        10 => (b + r, g + r, r),
        11 => (b, g + b, r + b),
        12 => (b, g + r + b, r + b),
        13 => (b + g, g + r + b + g, r + b + g),
        14 => (b + g + r, g + r, r + b + g + r),
        // All filter bytes were validated before the pixel loop.
        _ => (b, g + b * 2, r + b * 2),
    };
    [b as u8, g as u8, r as u8, a as u8]
}

#[cfg(test)]
#[path = "../../tests/krkr/tlg6.rs"]
mod tests;
