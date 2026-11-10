//! Cr6Ti predictive RGB/alpha coding. The channel correction order is G,R,B,
//! verified in the runtime decoder; the stream's runs are scoped to one row.
use super::{Meta, bad};
use crate::{Image, ImageMeta, OffsetUnit, PixelBuffer};
use vnlens_core::{Error, Result};
use vnlens_io::{BinaryReader, BitOrder, BitReader};

pub(super) fn metadata(r: &mut BinaryReader<'_>) -> Result<ImageMeta> {
    r.read_u32_le()?;
    r.read_bytes(4)?;
    let x = r.read_u16_le()? as i16;
    let y = r.read_u16_le()? as i16;
    let width = u32::from(r.read_u16_le()?);
    let height = u32::from(r.read_u16_le()?);
    Ok(ImageMeta {
        width,
        height,
        offset_x: i32::from(x),
        offset_y: i32::from(y),
        offset_unit: OffsetUnit::Pixels,
        bpp: 32,
    })
}

pub(super) fn unsigned(bits: &mut BitReader<'_>) -> Result<u32> {
    if bits.read_bit()? == 0 {
        return Ok(0);
    }
    let mut n = 1u32;
    loop {
        let bit = u32::from(bits.read_bit()?);
        n = n
            .checked_mul(2)
            .and_then(|n| n.checked_add(bit))
            .ok_or_else(|| bad(bits.position().0, "R6Ti run integer overflow"))?;
        if bits.read_bit()? == 0 {
            return Ok(n - 1);
        }
    }
}
pub(super) fn signed(bits: &mut BitReader<'_>) -> Result<i32> {
    if bits.read_bit()? == 0 {
        return Ok(0);
    }
    let sign = if bits.read_bit()? == 0 { 1 } else { -1 };
    let mut value = 1;
    for _ in 0..6 {
        if bits.read_bit()? == 0 {
            break;
        }
        value = value * 2 + i32::from(bits.read_bit()?);
    }
    Ok(value * sign)
}
fn signed_run(bits: &mut BitReader<'_>) -> Result<i64> {
    if bits.read_bit()? == 0 {
        return Ok(0);
    }
    let sign = if bits.read_bit()? == 0 { 1 } else { -1 };
    Ok((i64::from(unsigned(bits)?) + 1) * sign)
}
fn clamp(n: i32) -> i32 {
    n.clamp(0, 255)
}
fn store(
    out: &mut [u8],
    width: usize,
    x: &mut usize,
    y: usize,
    pixel: [i32; 4],
    count: usize,
) -> Result<()> {
    if count > width - *x {
        return Err(bad(0, "R6Ti run exceeds its row"));
    }
    for _ in 0..count {
        let offset = (y * width + *x) * 4;
        for (target, value) in out[offset..offset + 4].iter_mut().zip(pixel) {
            *target = value as u8;
        }
        *x += 1;
    }
    Ok(())
}
pub(super) fn decode(data: &[u8], m: &Meta) -> Result<Image> {
    let mut r = BinaryReader::new_at(data, m.body + if m.name == "CRmti" { 4 } else { 16 })?;
    let mut flags = if m.name == "CRmti" {
        0
    } else {
        r.read_u32_le()?
    };
    let mode = r.read_u8()?;
    let red = r.read_u8()?;
    let green = r.read_u8()?;
    let blue = r.read_u8()?;
    if m.name == "CRmti" {
        flags = if mode & 1 != 0 { 3 } else { 2 };
    }
    let codec = if m.name != "CRmti" && m.schema >= 2 {
        let codec = r.read_u8()?;
        r.read_u16_le()?;
        codec
    } else {
        0
    };
    // Image attachment reference: only a null attachment is self-contained.
    // External or inline attachments are exposed by the object graph reader.
    if m.name != "CRmti" {
        let padding = r.read_u8()?;
        if padding == 255 {
            r.read_u16_le()?;
        }
        if r.read_u16_le()? != 0 {
            return Err(Error::Unsupported("R6Ti attached image reference".into()));
        }
    }
    let length = r.read_u32_le()? as usize;
    let mut last_row = m.meta.height as usize;
    let encoded = if m.name == "CRmti" {
        r.read_u32_le()?;
        last_row = usize::from(r.read_u16_le()?);
        r.read_bytes(length)?
    } else {
        if m.schema >= 3 {
            r.read_u32_le()?;
        }
        r.read_u32_le()?;
        r.read_bytes(length.div_ceil(2) * 2 + 2)?
    };
    if codec == 2 {
        return Err(Error::Unsupported("R6Ti codec revision 2".into()));
    }
    if ![red, green, blue].into_iter().all(|v| (1..=8).contains(&v)) {
        return Err(bad(r.position(), "Invalid R6Ti channel depth"));
    }
    let mut bits = BitReader::new(
        encoded,
        if m.name == "CRmti" && mode & 8 == 0 {
            BitOrder::Msb
        } else {
            BitOrder::Lsb
        },
    );
    let mut out = vec![0; m.meta.rgba_size()?];
    let width = m.meta.width as usize;
    let height = m.meta.height as usize;
    let mut rows = Vec::new();
    if m.name == "CRmti" {
        if last_row > height {
            return Err(bad(r.position(), "RMTI final row exceeds image height"));
        }
        let (mut left, mut count) = (0i64, 0i64);
        for _ in 0..last_row {
            count += signed_run(&mut bits)?;
            if count > 0 {
                left += signed_run(&mut bits)?;
            } else {
                left = 0;
            }
            if left < 0 || count < 0 || left + count > width as i64 {
                return Err(bad(
                    bits.position().0,
                    "RMTI row extent exceeds image width",
                ));
            }
            rows.push((left as usize, (left + count) as usize));
        }
    }
    let alpha = flags & 255 == 3;
    if !matches!(flags & 255, 2 | 3) {
        return Err(Error::Unsupported(format!(
            "R6Ti pixel mode {}",
            flags & 255
        )));
    }
    for y in 0..last_row {
        let (mut x, end) = rows.get(y).copied().unwrap_or((0, width));
        let (mut red_value, mut g, mut b, mut dg) = (0, 0, 0, 0);
        let (mut alpha_value, mut same_alpha, mut same_color, mut repeated) =
            (0i32, 0i64, 0i64, true);
        let mut until_run = -1i64;
        while x < end {
            let a;
            if alpha {
                same_alpha -= 1;
                if same_alpha < 0 {
                    alpha_value += signed(&mut bits)?;
                    if !(0..=32).contains(&alpha_value) {
                        return Err(bad(bits.position().0, "Invalid R6Ti alpha predictor"));
                    }
                    if alpha_value == 0 {
                        let count = unsigned(&mut bits)? as usize + 1;
                        store(&mut out, width, &mut x, y, [0, 0, 0, 0], count)?;
                        continue;
                    }
                    if alpha_value == 32 {
                        same_alpha = i64::from(unsigned(&mut bits)?);
                    }
                }
                a = clamp(alpha_value * 8);
                same_color -= 1;
                if same_color < 0 {
                    repeated = !repeated;
                    same_color = i64::from(unsigned(&mut bits)?);
                    dg = 0;
                }
                if repeated {
                    let count = if same_alpha < same_color {
                        1
                    } else {
                        same_alpha -= same_color;
                        let count = same_color + 1;
                        same_color = 0;
                        count as usize
                    };
                    store(&mut out, width, &mut x, y, [red_value, g, b, a], count)?;
                    continue;
                }
            } else {
                a = 255;
                if until_run < 0 {
                    until_run = i64::from(unsigned(&mut bits)?);
                }
            }
            if bits.read_bit()? != 0 {
                if y == 0 {
                    red_value = 0;
                    g = 0;
                    b = 0;
                } else {
                    let previous = ((y - 1) * width + x) * 4;
                    red_value = i32::from(out[previous]);
                    g = i32::from(out[previous + 1]);
                    b = i32::from(out[previous + 2]);
                }
                dg = 0;
            } else if mode & 4 != 0 || alpha {
                let predicted = clamp(g + dg * 2) - g;
                let predicted = if alpha {
                    i32::from(predicted as i8)
                } else {
                    predicted
                };
                dg = (signed(&mut bits)? + predicted / 2).clamp(-128, 127);
                red_value = clamp(red_value + dg * 2);
                g = clamp(g + dg * 2);
                b = clamp(b + dg * 2);
                red_value = clamp(red_value + signed(&mut bits)? * 2);
                b = clamp(b + signed(&mut bits)? * 2);
                if alpha {
                    red_value &= 254;
                    g &= 254;
                    b &= 254;
                }
            } else {
                let delta = signed(&mut bits)? * (1 << (8 - green));
                red_value = clamp(red_value + delta);
                g = clamp(g + delta);
                b = clamp(b + delta);
                red_value = clamp(red_value + signed(&mut bits)? * (1 << (8 - red)))
                    & (256 - (1 << (8 - red)));
                g &= 256 - (1 << (8 - green));
                b = clamp(b + signed(&mut bits)? * (1 << (8 - blue))) & (256 - (1 << (8 - blue)));
            }
            store(&mut out, width, &mut x, y, [red_value, g, b, a], 1)?;
            if !alpha {
                until_run -= 1;
                if until_run < 0 && x < width {
                    let count = unsigned(&mut bits)? as usize + 1;
                    store(&mut out, width, &mut x, y, [red_value, g, b, 255], count)?;
                    dg = 0;
                }
            }
        }
    }
    Ok(Image {
        meta: m.meta.clone(),
        pixels: PixelBuffer::Rgba8(out),
    })
}

#[cfg(test)]
#[path = "../../tests/rugp/r6ti.rs"]
mod tests;
