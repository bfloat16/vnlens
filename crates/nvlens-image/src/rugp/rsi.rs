//! CRsi selected-frame transport from the archive domain: NVLRSI\0\x01,
//! u16 width/height, u32 dependency count, then u8 mode, u16 codec flags,
//! u16 repeat threshold, u32 length and unchanged frame bytes (all LE).
//! Decode the nearest key frame and its following deltas into one image.
//! The native YUV 2x2 codec follows rvmm 10074F70/10075920; 10056AD0
//! selects it from flag bits 10..12. No runtime DLL or SIMD is required.
use super::{
    bad,
    r6ti::{signed, unsigned},
};
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer};
use nvlens_core::{Error, Format, Result};
use nvlens_io::{BinaryReader, BitOrder, BitReader};

const MAGIC: &[u8; 8] = b"NVLRSI\0\x01";

#[derive(Debug, Default)]
struct Frame;
impl Format for Frame {
    fn tag(&self) -> &'static str {
        "frame/rugp"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x524c_564e]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["crsi_frame"]
    }
    fn description(&self) -> &'static str {
        "rUGP CRsi frame with its decoding dependencies"
    }
}
impl ImageFormat for Frame {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        if !data.starts_with(MAGIC) {
            return Ok(None);
        }
        let mut r = BinaryReader::new_at(data, MAGIC.len())?;
        let width = u32::from(r.read_u16_le()?);
        let height = u32::from(r.read_u16_le()?);
        if width == 0 || height == 0 {
            return Err(bad(8, "CRsi frame has empty dimensions"));
        }
        Ok(Some(ImageMeta {
            width,
            height,
            offset_x: 0,
            offset_y: 0,
            offset_unit: OffsetUnit::Pixels,
            bpp: 32,
        }))
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        let meta = self.metadata(data)?.ok_or(Error::InvalidFormat)?;
        let mut r = BinaryReader::new_at(data, 12)?;
        let count = r.read_u32_le()?;
        if count == 0 {
            return Err(bad(12, "CRsi frame has no encoded dependencies"));
        }
        let mut pixels = vec![0; meta.rgba_size()?];
        for i in 0..count {
            let key = r.read_u8()? & 1 != 0;
            let flags = r.read_u16_le()?;
            let threshold = r.read_u16_le()?;
            let length = r.read_u32_le()? as usize;
            let encoded = r.read_bytes(length)?;
            if i == 0 && !key {
                return Err(bad(
                    r.position(),
                    "CRsi dependency chain starts with a delta",
                ));
            }
            if flags & 0x200 != 0 {
                return Err(Error::Unsupported("CRsi alpha frame codec".into()));
            }
            let depths = [
                (flags & 7) + 1,
                ((flags >> 3) & 7) + 1,
                ((flags >> 6) & 7) + 1,
            ];
            match (flags >> 10) & 7 {
                1 => yuv(encoded, &meta, &mut pixels, depths, threshold, key)?,
                0 => rgb(encoded, &meta, &mut pixels, depths, key)?,
                codec => return Err(Error::Unsupported(format!("CRsi frame codec {codec}"))),
            }
        }
        if r.remaining() != 0 {
            return Err(bad(r.position(), "CRsi frame transport has trailing bytes"));
        }
        Ok(Image {
            meta,
            pixels: PixelBuffer::Rgba8(pixels),
        })
    }
}
nvlens_core::inventory::submit! {ImageRegistration(|| Box::new(Frame))}

fn run(bits: &mut BitReader<'_>, remaining: usize) -> Result<usize> {
    let count = usize::try_from(u64::from(unsigned(bits)?) + 1)
        .map_err(|_| bad(bits.position().0, "CRsi run exceeds address space"))?;
    if count > remaining {
        return Err(bad(bits.position().0, "CRsi run exceeds its row"));
    }
    Ok(count)
}

fn rgb(
    data: &[u8],
    meta: &ImageMeta,
    pixels: &mut [u8],
    depths: [u16; 3],
    key: bool,
) -> Result<()> {
    let width = meta.width as usize;
    let mut above = vec![[0i32; 3]; width];
    let mut bits = BitReader::new(data, BitOrder::Lsb);
    for y in 0..meta.height as usize {
        let mut left = [0i32; 3];
        let mut x = 0;
        while x < width {
            let n = run(&mut bits, width - x)?;
            for _ in 0..n {
                if bits.read_bit()? != 0 {
                    left = above[x];
                } else {
                    let dg = signed(&mut bits)? * (1 << (8 - depths[1]));
                    for value in &mut left {
                        *value = (*value + dg).clamp(0, 255);
                    }
                    left[0] = (left[0] + signed(&mut bits)? * (1 << (8 - depths[0]))).clamp(0, 255);
                    left[2] = (left[2] + signed(&mut bits)? * (1 << (8 - depths[2]))).clamp(0, 255);
                    for (v, depth) in left.iter_mut().zip(depths) {
                        *v &= 256 - (1 << (8 - depth));
                    }
                }
                above[x] = left;
                put(pixels, width, x, y, [left[2], left[1], left[0]], key);
                x += 1;
            }
            if x < width {
                let n = run(&mut bits, width - x)?;
                for _ in 0..n {
                    above[x] = left;
                    put(pixels, width, x, y, [left[2], left[1], left[0]], key);
                    x += 1;
                }
            }
        }
    }
    Ok(())
}

fn put(pixels: &mut [u8], width: usize, x: usize, y: usize, rgb: [i32; 3], key: bool) {
    let at = (y * width + x) * 4;
    for (p, v) in pixels[at..at + 3].iter_mut().zip(rgb) {
        *p = if key {
            v
        } else {
            (i32::from(*p) + 2 * (v - 128)).clamp(0, 255)
        } as u8;
    }
    pixels[at + 3] = 255;
}

// Lane order is Y, Cb, Cr. These are the signed high-word products of
// the native packed constant D24A59BAEA027168, followed by unsigned packing.
fn color(v: [i32; 3]) -> [i32; 3] {
    let [y, cb, cr] = v;
    [
        (y + ((cr * 22970) >> 16)).clamp(0, 255),
        (y + ((cb * -5630) >> 16) + ((cr * -11702) >> 16)).clamp(0, 255),
        (y + ((cb * 29032) >> 16)).clamp(0, 255),
    ]
}

fn average(a: [i32; 3], b: [i32; 3]) -> [i32; 3] {
    std::array::from_fn(|i| ((a[i] + b[i]) as i16 >> 1) as i32)
}

fn residual(bits: &mut BitReader<'_>, difference: i32) -> Result<i32> {
    let column = if bits.read_bit()? != 0 {
        4
    } else if bits.read_bit()? != 0 {
        if bits.read_bit()? != 0 { 3 } else { 5 }
    } else if bits.read_bit()? != 0 {
        if bits.read_bit()? != 0 { 2 } else { 6 }
    } else if bits.read_bit()? != 0 {
        if bits.read_bit()? != 0 { 7 } else { 1 }
    } else if bits.read_bit()? != 0 {
        0
    } else {
        return Ok(bits.read_bits_le(7)? as i32 * 4 - 256);
    };
    if difference.unsigned_abs() < 24 {
        let v = CURVE[difference.unsigned_abs() as usize][column];
        Ok(if difference < 0 { -v } else { v })
    } else {
        let d = f64::from(difference);
        Ok(
            (((column as f64 - 4.) * (40. / (d.abs() + 25.) + 0.64) * d + 2. * d) * 0.25 + 0.5)
                .floor() as i32,
        )
    }
}

fn yuv(
    data: &[u8],
    meta: &ImageMeta,
    pixels: &mut [u8],
    depths: [u16; 3],
    threshold: u16,
    key: bool,
) -> Result<()> {
    let width = meta.width as usize;
    let height = meta.height as usize;
    let columns = width.div_ceil(2);
    let mut above = vec![[0i32; 3]; columns];
    let mut bits = BitReader::new(data, BitOrder::Lsb);
    let threshold = if threshold == 0 {
        0x7fff
    } else {
        usize::from(threshold - 1)
    };
    for y in (0..height).step_by(2) {
        let mut left = [128, 0, 0];
        let mut corner = [0, 0, 0];
        let mut x = 0;
        while x < columns {
            let n = run(&mut bits, columns - x)?;
            let mut repeated = [0; 3];
            for _ in 0..n {
                let old = left;
                let top = above[x];
                let copied = bits.read_bit()? != 0;
                if copied {
                    left = top;
                } else {
                    left = std::array::from_fn(|i| {
                        (left[i] + top[i] + i32::from(key && i != 0)).clamp(-32768, 32767) >> 1
                    });
                    let dy = signed(&mut bits)?;
                    if key {
                        left[0] = (left[0] + ((dy << 7) >> depths[1]) * 2).clamp(0, 255);
                    } else {
                        left[0] =
                            (left[0] + ((dy << 8) >> depths[1])) & (0xffff << (8 - depths[1]));
                    }
                    for (i, depth) in [(2, depths[0]), (1, depths[2])] {
                        let delta = signed(&mut bits)?;
                        let shift = depth as i32 - 2;
                        let correction = if shift < 0 {
                            if delta < 0 { -1 } else { 0 }
                        } else {
                            (delta << 8) >> shift
                        };
                        if !key {
                            left[i] &= (-1i32) << (10 - depth);
                        }
                        left[i] = (left[i] + correction).clamp(-32768, 32767);
                    }
                }
                let flat = bits.read_bit()? != 0;
                let preserve = !key && !flat && bits.read_bit()? != 0;
                let block = if flat || preserve {
                    [color(left); 4]
                } else {
                    let mut right = if copied { left } else { average(top, left) };
                    if !copied {
                        right[0] = (top[0] + residual(&mut bits, left[0] - top[0])?).clamp(0, 255);
                    }
                    let mut bottom_left = average(old, left);
                    bottom_left[0] = old[0] + residual(&mut bits, left[0] - old[0])?;
                    let mut top_left = average(corner, right);
                    top_left[0] = corner[0] + residual(&mut bits, right[0] - corner[0])?;
                    corner = right;
                    [
                        color(top_left),
                        color(right),
                        color(bottom_left),
                        color(left),
                    ]
                };
                if flat || preserve {
                    corner = left;
                }
                above[x] = left;
                // Delta flat mode copies the previous bottom-right pixel before
                // applying its residual to the complete 2x2 block.
                if !key && flat {
                    let px = (2 * x + 1).min(width - 1);
                    let py = (y + 1).min(height - 1);
                    let at = (py * width + px) * 4;
                    let base = [pixels[at], pixels[at + 1], pixels[at + 2]];
                    for dy in 0..2 {
                        for dx in 0..2 {
                            if 2 * x + dx < width && y + dy < height {
                                let at = ((y + dy) * width + 2 * x + dx) * 4;
                                pixels[at..at + 3].copy_from_slice(&base);
                            }
                        }
                    }
                }
                for dy in 0..2 {
                    for dx in 0..2 {
                        if 2 * x + dx < width && y + dy < height {
                            put(pixels, width, 2 * x + dx, y + dy, block[dy * 2 + dx], key);
                        }
                    }
                }
                repeated = block[3];
                x += 1;
            }
            if x < columns {
                let n = run(&mut bits, columns - x)?;
                if key && n > threshold {
                    let code = bits.read_bits_le(6)? as usize;
                    left[0] = (left[0] + [0, 1, 2, 4][code & 3]).clamp(0, 255);
                    left[1] = (left[1] + [-12, -4, 0, 4][code >> 4]).clamp(-32768, 32767);
                    left[2] = (left[2] + [-12, -4, 0, 4][(code >> 2) & 3]).clamp(-32768, 32767);
                    repeated = color(left);
                }
                for _ in 0..n {
                    above[x] = left;
                    for dy in 0..2 {
                        for dx in 0..2 {
                            if 2 * x + dx < width && y + dy < height {
                                put(pixels, width, 2 * x + dx, y + dy, repeated, key);
                            }
                        }
                    }
                    x += 1;
                }
                corner = left;
            }
        }
    }
    Ok(())
}

// Small-difference corrections from rvmm 1008CB28, used by 10074A60.
const CURVE: [[i32; 8]; 24] = [
    [-32, 16, -8, -2, 0, 2, 6, 40],
    [-32, 16, -8, -2, 1, 3, 7, 40],
    [-32, 16, -7, -1, 1, 3, 8, 40],
    [-32, 16, -7, -1, 2, 4, 8, 40],
    [-32, -8, -2, 0, 2, 4, 8, 40],
    [-32, -8, -2, 0, 3, 5, 9, 40],
    [-32, -8, -2, 0, 3, 5, 10, 40],
    [-32, -8, -2, 0, 4, 6, 12, 40],
    [-32, -8, -3, 1, 4, 8, 16, 40],
    [-32, -8, -3, 1, 5, 9, 17, 40],
    [-32, -9, -3, 1, 5, 9, 18, 40],
    [-32, -9, -3, 1, 6, 10, 18, 40],
    [-32, -10, -3, 1, 6, 12, 20, 40],
    [-32, -10, -3, 2, 7, 12, 20, 40],
    [-32, -11, -4, 2, 7, 14, 23, 40],
    [-32, -11, -4, 2, 7, 14, 23, 40],
    [-30, -11, -4, 3, 8, 15, 24, 40],
    [-30, -11, -4, 3, 8, 16, 25, 40],
    [-29, -12, -4, 3, 8, 17, 27, 40],
    [-29, -12, -4, 3, 8, 17, 27, 40],
    [-28, -12, -4, 4, 9, 18, 28, 40],
    [-28, -12, -4, 4, 9, 18, 29, 40],
    [-28, -12, -4, 4, 9, 19, 30, 40],
    [-28, -12, -4, 4, 9, 19, 30, 40],
];

#[cfg(test)]
#[path = "../../tests/rugp/rsi.rs"]
mod tests;
