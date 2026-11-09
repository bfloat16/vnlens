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
#[path = "../../tests/yuris/ycg.rs"]
mod tests;
