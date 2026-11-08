//! ExHIBIT GYU: little-endian 36-byte header, BGRA palette, scrambled color
//! stream and optional separate alpha plane. Rows are stored bottom-up.
//! Compression and palette layout follow GARbro's ExHibit/GyuReader.

mod dlt;

use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, PixelBuffer};
use nvlens_core::{Error, Format, Result};
use nvlens_io::BinaryReader;

#[derive(Debug, Default)]
struct Gyu;
impl Format for Gyu {
    fn tag(&self) -> &'static str {
        "gyu/exhibit"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x1a55_5947]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["gyu", "lvg"]
    }
    fn description(&self) -> &'static str {
        "ExHIBIT GYU image"
    }
}
impl ImageFormat for Gyu {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        if !data.starts_with(b"GYU\x1a") {
            return Ok(None);
        }
        Ok(Some(Header::parse(data)?.meta))
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        decode(data)
    }
}
nvlens_core::inventory::submit! { ImageRegistration(|| Box::new(Gyu)) }

struct Header {
    meta: ImageMeta,
    flags: u16,
    mode: u16,
    seed: u32,
    color_size: usize,
    alpha_size: usize,
    colors: usize,
}
impl Header {
    fn parse(data: &[u8]) -> Result<Self> {
        let mut r = BinaryReader::new(data);
        if r.read_u32_le()? != 0x1a55_5947 {
            return Err(Error::InvalidFormat);
        }
        let flags = r.read_u16_le()?;
        let mode = r.read_u16_le()?;
        let seed = r.read_u32_le()?;
        let depth = r.read_u32_le()?;
        if !matches!(depth, 8 | 24 | 32) {
            return Err(Error::Unsupported(format!("GYU bit depth {depth}")));
        }
        let meta = ImageMeta {
            width: r.read_u32_le()?,
            height: r.read_u32_le()?,
            offset_x: 0,
            offset_y: 0,
            offset_unit: crate::OffsetUnit::Pixels,
            bpp: depth as u16,
        };
        if meta.width == 0 || meta.height == 0 {
            return Err(corrupt(16, "Empty GYU image"));
        }
        meta.rgba_size()?;
        let color_size = r.read_u32_le()? as usize;
        let alpha_size = r.read_u32_le()? as usize;
        let colors = r.read_u32_le()? as usize;
        if depth == 8 && colors == 0 {
            return Err(corrupt(32, "GYU palette is missing"));
        }
        Ok(Self {
            meta,
            flags,
            mode,
            seed,
            color_size,
            alpha_size,
            colors,
        })
    }
}
fn corrupt(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
fn decode(data: &[u8]) -> Result<Image> {
    let h = Header::parse(data)?;
    if h.seed == 0 {
        return Err(Error::UnknownScheme(Some(
            "GYU requires an external image seed".into(),
        )));
    }
    let mut r = BinaryReader::new_at(data, 36)?;
    let palette_size = h
        .colors
        .checked_mul(4)
        .ok_or_else(|| corrupt(32, "GYU palette size overflow"))?;
    let palette = r.read_bytes(palette_size)?;
    let mut packed = r.read_bytes(h.color_size)?.to_vec();
    nvlens_crypto::cipher::exhibit::unscramble(&mut packed, h.seed);
    let width = h.meta.width as usize;
    let height = h.meta.height as usize;
    let pixel_size = usize::from(h.meta.bpp / 8);
    let stride = (width * pixel_size + 3) & !3;
    let size = stride
        .checked_mul(height)
        .ok_or_else(|| corrupt(16, "GYU storage size overflow"))?;
    let color = match h.mode {
        0x100 => {
            if packed.len() != size {
                return Err(corrupt(24, "GYU color size differs from dimensions"));
            }
            packed
        }
        0x400 => nvlens_crypto::compress::exhibit::lzss(&packed, size)?,
        0x800 => nvlens_crypto::compress::exhibit::gyu(&packed, size)?,
        _ => {
            return Err(Error::Unsupported(format!(
                "GYU compression mode {:#x}",
                h.mode
            )));
        }
    };
    let alpha_stride = (width + 3) & !3;
    let alpha = if h.alpha_size != 0 {
        let encoded = r.read_bytes(h.alpha_size)?;
        let size = alpha_stride
            .checked_mul(height)
            .ok_or_else(|| corrupt(16, "GYU alpha size overflow"))?;
        Some(if encoded.len() == size {
            encoded.to_vec()
        } else {
            nvlens_crypto::compress::exhibit::lzss(encoded, size)?
        })
    } else {
        None
    };
    let mut pixels = Vec::with_capacity(h.meta.rgba_size()?);
    for y in (0..height).rev() {
        for x in 0..width {
            let pos = y * stride + x * pixel_size;
            let bgr = if pixel_size == 1 {
                let entry = usize::from(color[pos]) * 4;
                palette
                    .get(entry..entry + 3)
                    .ok_or_else(|| corrupt(pos, "GYU palette index is absent"))?
            } else {
                &color[pos..pos + 3]
            };
            let a = alpha.as_ref().map_or(255, |plane| {
                let a = plane[y * alpha_stride + x];
                if h.flags == 3 {
                    a
                } else if a >= 16 {
                    255
                } else {
                    a * 16
                }
            });
            pixels.extend([bgr[2], bgr[1], bgr[0], a]);
        }
    }
    Ok(Image {
        meta: h.meta,
        pixels: PixelBuffer::Rgba8(pixels),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;

    fn raw(flags: u32, depth: u32, colors: &[u8], alpha: &[u8], palette: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 36];
        for (i, value) in [
            0x1a55_5947,
            0x0100_0000 | flags,
            u32::MAX,
            depth,
            1,
            2,
            colors.len() as u32,
            alpha.len() as u32,
            (palette.len() / 4) as u32,
        ]
        .into_iter()
        .enumerate()
        {
            BinaryWriter::u32_le(value, &mut bytes[i * 4..]);
        }
        bytes.extend_from_slice(palette);
        bytes.extend_from_slice(colors);
        bytes.extend_from_slice(alpha);
        bytes
    }

    #[test]
    fn raw_bottom_up_rows_palette_and_alpha_precision() {
        let data = raw(
            3,
            24,
            &[1, 2, 3, 0, 4, 5, 6, 0],
            &[7, 0, 0, 0, 8, 0, 0, 0],
            &[],
        );
        let PixelBuffer::Rgba8(pixels) = decode(&data).unwrap().pixels else {
            return;
        };
        assert_eq!(pixels, [6, 5, 4, 8, 3, 2, 1, 7]);
        let data = raw(
            1,
            8,
            &[1, 0, 0, 0, 0, 0, 0, 0],
            &[16, 0, 0, 0, 8, 0, 0, 0],
            &[1, 2, 3, 0, 4, 5, 6, 0],
        );
        let PixelBuffer::Rgba8(pixels) = decode(&data).unwrap().pixels else {
            return;
        };
        assert_eq!(pixels, [3, 2, 1, 128, 6, 5, 4, 255]);
        for len in [3, 35, data.len() - 1] {
            assert!(decode(&data[..len]).is_err());
        }
        let mut invalid = data.clone();
        invalid[44] = 2;
        assert!(decode(&invalid).is_err());
    }
}
