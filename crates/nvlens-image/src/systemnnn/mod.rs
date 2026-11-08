//! DWQ uses a 64-byte envelope with an ASCII PACKTYPE field at +48.
//! PNG (8) and JPEG (5) carry standard images. BMP (0) uses NNN's top-down
//! rows and RGB byte order, even with a positive BITMAPINFOHEADER height.
//! See NNNLib CPicture and GARbro BlackCyc.DwqFormat for the BMP variant.
// BMP layout adapted from GARbro, Copyright (C) 2015-2017 morkt, MIT.
use crate::{
    Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer, standard::Raster,
};
use nvlens_core::{Error, Format, Result};
use nvlens_io::BinaryReader;

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
nvlens_core::inventory::submit! {ImageRegistration(||Box::new(Dwq))}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;
    fn envelope(payload: &[u8], kind: u8, width: u32, height: u32) -> Vec<u8> {
        let mut data = vec![b' '; 64];
        data[..4].copy_from_slice(if kind == 8 { b"PNG " } else { b"BMP " });
        BinaryWriter::u32_le(width, &mut data[36..]);
        BinaryWriter::u32_le(height, &mut data[40..]);
        let field = format!("PACKTYPE={kind}");
        data[48..48 + field.len()].copy_from_slice(field.as_bytes());
        data.extend_from_slice(payload);
        data
    }
    fn bmp(depth: u16, width: u32, height: u32, palette: &[u8], rows: &[u8]) -> Vec<u8> {
        let mut data = vec![0; 54];
        data[..2].copy_from_slice(b"BM");
        // Converter fields intentionally differ from physical storage.
        BinaryWriter::u32_le(999, &mut data[2..]);
        BinaryWriter::u32_le(777, &mut data[10..]);
        BinaryWriter::u32_le(40, &mut data[14..]);
        BinaryWriter::u32_le(width, &mut data[18..]);
        BinaryWriter::u32_le(height, &mut data[22..]);
        BinaryWriter::u16_le(1, &mut data[26..]);
        BinaryWriter::u16_le(depth, &mut data[28..]);
        BinaryWriter::u32_le((palette.len() / 4) as u32, &mut data[46..]);
        data.extend_from_slice(palette);
        data.extend_from_slice(rows);
        data
    }
    #[test]
    fn indexed_bmp_uses_sequential_palette_top_down_rows_and_no_resource_conflict() {
        let payload = bmp(
            8,
            3,
            2,
            &[0, 0, 255, 0, 255, 0, 0, 0],
            &[0, 1, 0, 99, 1, 0, 1, 99],
        );
        let data = envelope(&payload, 0, 3, 2);
        let expected = vec![
            255, 0, 0, 255, 0, 0, 255, 255, 255, 0, 0, 255, 0, 0, 255, 255, 255, 0, 0, 255, 0, 0,
            255, 255,
        ];
        let image = crate::decode(&data).unwrap().unwrap();
        assert!(matches!(image.pixels,PixelBuffer::Rgba8(p) if p==expected));
        for len in 0..data.len() {
            assert!(Dwq.decode(&data[..len]).is_err());
        }
        let mut bad = data.clone();
        bad[64 + 54 + 8] = 2;
        assert!(Dwq.decode(&bad).is_err());
        let mut bad = data;
        BinaryWriter::u32_le(4, &mut bad[36..]);
        assert!(Dwq.metadata(&bad).is_err());
    }
    #[test]
    fn bmp_rgb565_rgb24_rgb32_and_legacy_header() {
        for (depth, bytes, expected) in [
            (16, vec![0x1f, 0, 0, 0], vec![0, 0, 255, 255]),
            (24, vec![10, 20, 30, 0], vec![10, 20, 30, 255]),
            (32, vec![10, 20, 30, 0], vec![10, 20, 30, 255]),
        ] {
            let mut data = envelope(&bmp(depth, 1, 1, &[], &bytes), 0, 1, 1);
            assert!(
                matches!(Dwq.decode(&data).unwrap().pixels,PixelBuffer::Rgba8(p) if p==expected)
            );
            data[..48].copy_from_slice(b"IF PACKTYPE==0  CUT THIS 64 BYTETHEN REMAKE BMP ");
            assert!(
                matches!(Dwq.decode(&data).unwrap().pixels,PixelBuffer::Rgba8(p) if p==expected)
            );
        }
    }
    #[test]
    fn png_preserves_alpha_offsets_and_rejects_outer_dimension_mismatch() {
        let image = Image {
            meta: ImageMeta {
                width: 1,
                height: 1,
                offset_x: -3,
                offset_y: 7,
                offset_unit: OffsetUnit::Pixels,
                bpp: 32,
            },
            pixels: PixelBuffer::Rgba8(vec![1, 2, 3, 4]),
        };
        let mut data = envelope(&image.to_png().unwrap(), 8, 1, 1);
        let decoded = Dwq.decode(&data).unwrap();
        assert_eq!(decoded.meta, image.meta);
        assert!(matches!(decoded.pixels,PixelBuffer::Rgba8(p) if p==[1,2,3,4]));
        data[58] = b'A';
        assert!(Dwq.decode(&data).is_ok());
        BinaryWriter::u32_le(2, &mut data[40..]);
        assert!(Dwq.decode(&data).is_err());
        assert!(Dwq.metadata(b"not an image").unwrap().is_none());
    }
}
