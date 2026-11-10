//! DWQ uses a 64-byte envelope with an ASCII PACKTYPE field at +48.
//! PNG (8) and JPEG (5) carry standard images. BMP (0) uses NNN's top-down
//! rows and RGB byte order, even with a positive BITMAPINFOHEADER height.
//! See NNNLib CPicture and GARbro BlackCyc.DwqFormat for the BMP variant.
// BMP layout adapted from GARbro, Copyright (C) 2015-2017 morkt, MIT.
use crate::{
    Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer, standard::Raster,
};
use vnlens_core::{Error, Format, Result};
use vnlens_io::BinaryReader;

const SIGNATURES: &[u32] = &[0x2047_4e50, 0x4745_504a, 0x2050_4d42, 0x5020_4649];
#[derive(Debug, Default)]
struct Dwq;
impl Format for Dwq {
    fn tag(&self) -> &'static str {
        "dwq/systemnnn"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["dwq"]
    }
    fn description(&self) -> &'static str {
        "SystemNNN DWQ PNG/JPEG/BMP images"
    }
}
fn header(data: &[u8]) -> Result<Option<(u8, &[u8])>> {
    if !(data.starts_with(b"PNG ")
        || data.starts_with(b"JPEG ")
        || data.starts_with(b"BMP ")
        || (data.starts_with(b"IF PACKTYPE==") && data.get(44..48) == Some(b"BMP ")))
    {
        return Ok(None);
    }
    let mut r = BinaryReader::new(data);
    r.read_bytes(48)?;
    let field = r.read_bytes(16)?.trim_ascii();
    let field = field.strip_suffix(b"A").unwrap_or(field);
    let kind = match field {
        b"PACKTYPE=0" => 0,
        b"PACKTYPE=5" => 5,
        b"PACKTYPE=8" => 8,
        _ => return Err(Error::Unsupported("DWQ packing method".into())),
    };
    Ok(Some((kind, &data[r.position()..])))
}
impl ImageFormat for Dwq {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        let Some((kind, payload)) = header(data)? else {
            return Ok(None);
        };
        let meta = if kind == 0 {
            bitmap(payload)?.0
        } else {
            if (kind == 8 && !payload.starts_with(b"\x89PNG\r\n\x1a\n"))
                || (kind == 5 && !payload.starts_with(b"\xff\xd8"))
            {
                return Err(Error::InvalidFormat);
            }
            Raster.metadata(payload)?.ok_or(Error::InvalidFormat)?
        };
        if !data.starts_with(b"IF PACKTYPE==") {
            let mut dimensions = BinaryReader::new_at(data, 36)?;
            if dimensions.read_u32_le()? != meta.width || dimensions.read_u32_le()? != meta.height {
                return Err(corrupt("DWQ and embedded image dimensions differ"));
            }
        }
        Ok(Some(meta))
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        let meta = self.metadata(data)?.ok_or(Error::InvalidFormat)?;
        let (kind, payload) = header(data)?.ok_or(Error::InvalidFormat)?;
        if kind != 0 {
            return Raster.decode(payload);
        }
        let (_, depth, palette, rows) = bitmap(payload)?;
        let pixel_size = usize::from(depth / 8);
        let stride = (meta.width as usize * pixel_size + 3) & !3;
        let mut pixels = Vec::with_capacity(meta.rgba_size()?);
        for row in rows.chunks_exact(stride) {
            for src in row[..meta.width as usize * pixel_size].chunks_exact(pixel_size) {
                let color = match depth {
                    8 => {
                        let at = usize::from(src[0]) * 4;
                        let p = palette
                            .get(at..at + 4)
                            .ok_or_else(|| corrupt("DWQ palette index is out of range"))?;
                        [p[2], p[1], p[0], 255]
                    }
                    16 => {
                        let value = BinaryReader::u16_le(src);
                        let r = ((value >> 11) & 31) as u8;
                        let g = ((value >> 5) & 63) as u8;
                        let b = (value & 31) as u8;
                        [
                            (r << 3) | (r >> 2),
                            (g << 2) | (g >> 4),
                            (b << 3) | (b >> 2),
                            255,
                        ]
                    }
                    _ => [src[0], src[1], src[2], 255],
                };
                pixels.extend_from_slice(&color);
            }
        }
        Ok(Image {
            meta,
            pixels: PixelBuffer::Rgba8(pixels),
        })
    }
}
// The stored bfSize/bfOffBits can include converter padding absent on disk.
// CPicture reads the 54-byte header, palette, then row bytes sequentially.
fn bitmap(data: &[u8]) -> Result<(ImageMeta, u16, &[u8], &[u8])> {
    let mut r = BinaryReader::new(data);
    if r.read_bytes(2)? != b"BM" {
        return Err(Error::InvalidFormat);
    }
    r.read_bytes(12)?;
    if r.read_u32_le()? != 40 {
        return Err(Error::Unsupported("DWQ BMP DIB header".into()));
    }
    let width = r.read_u32_le()? as i32;
    let height = r.read_u32_le()? as i32;
    let planes = r.read_u16_le()?;
    let depth = r.read_u16_le()?;
    let compression = r.read_u32_le()?;
    r.read_bytes(12)?;
    let colors = r.read_u32_le()?;
    r.read_u32_le()?;
    if width <= 0 || height == 0 || planes != 1 {
        return Err(corrupt("Invalid DWQ BMP dimensions/planes"));
    }
    if compression != 0 || !matches!(depth, 8 | 16 | 24 | 32) {
        return Err(Error::Unsupported("DWQ BMP pixel layout".into()));
    }
    let palette = if depth == 8 {
        let count = if colors == 0 { 256 } else { colors };
        if count > 256 {
            return Err(corrupt("DWQ palette exceeds 8-bit indices"));
        }
        r.read_bytes(count as usize * 4)?
    } else {
        &[]
    };
    let stride = (u64::from(width as u32) * u64::from(depth / 8) + 3) & !3;
    let size = usize::try_from(stride * u64::from(height.unsigned_abs()))
        .map_err(|_| Error::Unsupported("DWQ BMP exceeds address space".into()))?;
    let rows = r.read_bytes(size)?;
    Ok((
        ImageMeta {
            width: width as u32,
            height: height.unsigned_abs(),
            offset_x: 0,
            offset_y: 0,
            offset_unit: OffsetUnit::Pixels,
            bpp: 32,
        },
        depth,
        palette,
        rows,
    ))
}
fn corrupt(reason: &str) -> Error {
    Error::Corrupt {
        offset: 64,
        reason: reason.into(),
    }
}
vnlens_core::inventory::submit! {ImageRegistration(||Box::new(Dwq))}

#[cfg(test)]
#[path = "../../tests/systemnnn/mod.rs"]
mod tests;
