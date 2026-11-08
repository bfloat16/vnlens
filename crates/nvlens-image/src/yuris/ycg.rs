//! YCG, verified against YU-RIS client 0x40DD40: 0x38-byte header, BGRA
//! pixels, method 0 stored or method 1 two consecutive zlib streams.
use crate::{Image, ImageMeta, PixelBuffer};
use nvlens_core::{Error, Result};
use nvlens_io::BinaryReader;

pub(super) fn metadata(data: &[u8]) -> Result<ImageMeta> {
    let mut r = BinaryReader::new(data);
    r.read_bytes(4)?;
    let width = r.read_u32_le()?;
    let height = r.read_u32_le()?;
    let bpp = r.read_u32_le()?;
    if bpp != 32 {
        return Err(Error::Unsupported(format!("YCG pixel depth {bpp}")));
    }
    r.read_bytes(40)?;
    let meta = ImageMeta {
        width,
        height,
        offset_x: 0,
        offset_y: 0,
        offset_unit: crate::OffsetUnit::Pixels,
        bpp: 32,
    };
    meta.rgba_size()?;
    Ok(meta)
}
pub(super) fn decode(data: &[u8]) -> Result<Image> {
    let meta = metadata(data)?;
    let expected = meta.rgba_size()?;
    let method = BinaryReader::u32_le(&data[16..]);
    let mut reader = BinaryReader::new_at(data, 56)?;
    let pixels = match method {
        0 => reader.read_bytes(expected)?.to_vec(),
        1 => {
            let raw1 = BinaryReader::u32_le(&data[32..]) as usize;
            let packed1 = BinaryReader::u32_le(&data[36..]) as usize;
            let raw2 = BinaryReader::u32_le(&data[48..]) as usize;
            let packed2 = BinaryReader::u32_le(&data[52..]) as usize;
            if raw1.checked_add(raw2) != Some(expected) {
                return Err(corrupt("YCG decoded stream lengths do not match pixels"));
            }
            let mut pixels = Vec::new();
            for (packed, raw) in [(packed1, raw1), (packed2, raw2)] {
                let source = reader.read_bytes(packed)?;
                if raw == 0 && packed == 0 {
                    continue;
                }
                let bytes = nvlens_crypto::compress::zlib::inflate_with_limit(source, raw)
                    .map_err(|e| corrupt(&e.to_string()))?;
                if bytes.len() != raw {
                    return Err(corrupt("YCG stream length mismatch"));
                }
                pixels.extend(bytes);
            }
            pixels
        }
        _ => {
            return Err(Error::Unsupported(format!(
                "YCG compression method {method}"
            )));
        }
    };
    if reader.remaining() != 0 {
        return Err(corrupt("Trailing YCG pixel data"));
    }
    Ok(Image {
        meta,
        pixels: PixelBuffer::Bgra8(pixels),
    })
}
fn corrupt(reason: &str) -> Error {
    Error::Corrupt {
        offset: 16,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;
    #[test]
    fn decodes_bgra_and_preserves_png_offsets() {
        let mut bytes = vec![0; 56];
        bytes[..4].copy_from_slice(b"YCG\0");
        for (offset, value) in [(4, 2), (8, 1), (12, 32)] {
            BinaryWriter::u32_le(value, &mut bytes[offset..]);
        }
        bytes.extend([0, 0, 255, 255, 255, 0, 0, 128]);
        let mut image = decode(&bytes).unwrap();
        image.meta.offset_x = -3;
        image.meta.offset_y = 5;
        let png = image.to_png().unwrap();
        let decoded = crate::decode(&png).unwrap().unwrap();
        assert_eq!(decoded.meta, image.meta);
        let PixelBuffer::Rgba8(pixels) = decoded.pixels else {
            return;
        };
        assert_eq!(pixels, [255, 0, 0, 255, 0, 0, 255, 128]);
        for end in 4..bytes.len() {
            assert!(decode(&bytes[..end]).is_err());
        }
    }
    #[test]
    fn reads_independent_zlib_blocks() {
        // Independent Python zlib vectors for one red and one blue BGRA pixel.
        let mut bytes = vec![0; 56];
        bytes[..4].copy_from_slice(b"YCG\0");
        for (offset, value) in [
            (4, 2),
            (8, 1),
            (12, 32),
            (16, 1),
            (32, 4),
            (36, 12),
            (48, 4),
            (52, 12),
        ] {
            BinaryWriter::u32_le(value, &mut bytes[offset..]);
        }
        bytes.extend([0x78, 0x9c, 0x63, 0x60, 0xf8, 0xff, 0x1f, 0, 3, 1, 1, 0xff]);
        bytes.extend([0x78, 0x9c, 0xfb, 0xcf, 0xc0, 0xd0, 0, 0, 4, 0x80, 1, 0x80]);
        let image = decode(&bytes).unwrap();
        assert!(
            matches!(image.pixels,PixelBuffer::Bgra8(ref pixels) if pixels==&[0,0,255,255,255,0,0,128])
        );
        bytes[79] ^= 1;
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn png_export_retains_sixteen_bit_samples_and_offset_units() {
        let image = Image {
            meta: ImageMeta {
                width: 1,
                height: 1,
                bpp: 64,
                offset_x: 123,
                offset_y: -456,
                offset_unit: crate::OffsetUnit::Micrometers,
            },
            pixels: PixelBuffer::Rgba16(vec![1, 256, 65535, 65535]),
        };
        let png = image.to_png().unwrap();
        let decoded = crate::decode(&png).unwrap().unwrap();
        assert_eq!(decoded.meta, image.meta);
        assert!(
            matches!(decoded.pixels,PixelBuffer::Rgba16(ref values) if values==&[1,256,65535,65535])
        );
    }
}
