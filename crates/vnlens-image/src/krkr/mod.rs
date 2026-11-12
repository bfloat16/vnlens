//! TLG5/6 images, as specified by KiriKiri's LoadTLG.cpp/SaveTLG5.cpp.
//! Planar residuals use a shared slide dictionary, green decorrelation, then
//! horizontal and vertical predictors modulo 256. TLG0 tags carry pixel offsets.
mod pimg;
mod tlg6;
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer};
use vnlens_core::{Error, Format, Result};
use vnlens_crypto::compress::tlg::Slide;
use vnlens_io::BinaryReader;
const RAW: &[u8; 11] = b"TLG5.0\0raw\x1a";
const SDS: &[u8; 11] = b"TLG0.0\0sds\x1a";
const SIGNATURES: &[u32] = &[0x35474c54, 0x36474c54, 0x30474c54];
#[derive(Debug, Default)]
struct Tlg;
impl Format for Tlg {
    fn tag(&self) -> &'static str {
        "tlg/krkr"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["tlg"]
    }
    fn description(&self) -> &'static str {
        "KiriKiri TLG5/6 image"
    }
}
fn corrupt(reason: &str) -> Error {
    Error::Corrupt {
        offset: 0,
        reason: reason.into(),
    }
}
fn source(bytes: &[u8]) -> Result<(&[u8], i32, i32)> {
    if !bytes.starts_with(SDS) {
        return Ok((bytes, 0, 0));
    }
    let mut r = BinaryReader::new_at(bytes, 11)?;
    let size = r.read_u32_le()? as usize;
    let raw = r.read_bytes(size)?;
    let mut x = 0;
    let mut y = 0;
    while r.remaining() != 0 {
        let tag = r.read_bytes(4)?;
        let size = r.read_u32_le()? as usize;
        let data = r.read_bytes(size)?;
        if tag != b"tags" {
            continue;
        }
        let mut tags = BinaryReader::new(data);
        while tags.remaining() != 0 {
            let name = tag_string(&mut tags)?;
            if tags.read_u8()? != b'=' {
                return Err(corrupt("Invalid TLG tag separator"));
            }
            let value = tag_string(&mut tags)?;
            if tags.read_u8()? != b',' {
                return Err(corrupt("Invalid TLG tag terminator"));
            }
            match name {
                "offset_x" | "LEFT" => {
                    x = value
                        .parse()
                        .map_err(|_| corrupt("Invalid TLG horizontal offset"))?
                }
                "offset_y" | "TOP" => {
                    y = value
                        .parse()
                        .map_err(|_| corrupt("Invalid TLG vertical offset"))?
                }
                _ => {}
            }
        }
    }
    Ok((raw, x, y))
}
fn tag_string<'a>(r: &mut BinaryReader<'a>) -> Result<&'a str> {
    let mut size = 0usize;
    let mut digits = 0;
    loop {
        let b = r.read_u8()?;
        if b == b':' && digits != 0 {
            break;
        }
        if !b.is_ascii_digit() {
            return Err(corrupt("Invalid TLG tag length"));
        }
        size = size
            .checked_mul(10)
            .and_then(|n| n.checked_add(usize::from(b - b'0')))
            .ok_or_else(|| corrupt("TLG tag length overflow"))?;
        digits += 1;
    }
    std::str::from_utf8(r.read_bytes(size)?).map_err(|_| corrupt("Invalid TLG tag UTF-8"))
}
fn header(raw: &[u8], x: i32, y: i32) -> Result<(ImageMeta, usize)> {
    let mut r = BinaryReader::new(raw);
    if r.read_bytes(11)? != RAW {
        return Err(Error::Unsupported("TLG codec version".into()));
    }
    let colors = r.read_u8()?;
    let width = r.read_u32_le()?;
    let height = r.read_u32_le()?;
    let block = r.read_u32_le()?;
    if !matches!(colors, 1 | 3 | 4) {
        return Err(Error::Unsupported("TLG color count".into()));
    }
    if width == 0 || height == 0 || block == 0 {
        return Err(corrupt("Zero TLG dimensions or block height"));
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
    Ok((meta, block as usize))
}
impl ImageFormat for Tlg {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        if !data.starts_with(b"TLG5") && !data.starts_with(b"TLG6") && !data.starts_with(b"TLG0") {
            return Ok(None);
        }
        let (raw, x, y) = source(data)?;
        if raw.starts_with(tlg6::MAGIC) {
            return tlg6::header(raw, x, y).map(|(meta, _)| Some(meta));
        }
        header(raw, x, y).map(|(meta, _)| Some(meta))
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        let (raw, x, y) = source(data)?;
        if raw.starts_with(tlg6::MAGIC) {
            return tlg6::decode(raw, x, y);
        }
        let (meta, block_height) = header(raw, x, y)?;
        let width = meta.width as usize;
        let height = meta.height as usize;
        let colors = usize::from(meta.bpp / 8);
        let mut r = BinaryReader::new_at(raw, 24)?;
        let blocks = height.div_ceil(block_height);
        let mut sizes = Vec::new();
        for _ in 0..blocks {
            sizes.push(r.read_u32_le()? as usize);
        }
        let mut pixels = vec![0; meta.rgba_size()?];
        let mut slide = Slide::default();
        for (block, size) in sizes.into_iter().enumerate() {
            let y0 = block * block_height;
            let rows = block_height.min(height - y0);
            let plane_size = width * rows;
            let mut b = BinaryReader::new(r.read_bytes(size)?);
            let mut planes = Vec::new();
            for _ in 0..colors {
                let method = b.read_u8()?;
                let size = b.read_u32_le()? as usize;
                let bytes = b.read_bytes(size)?;
                let plane = match method {
                    0 => slide.decode(bytes, plane_size)?,
                    1 if size == plane_size => bytes.to_vec(),
                    1 => return Err(corrupt("TLG raw plane length mismatch")),
                    _ => return Err(Error::Unsupported("TLG plane encoding".into())),
                };
                planes.push(plane);
            }
            if b.remaining() != 0 {
                return Err(corrupt("TLG block length mismatch"));
            }
            for row in 0..rows {
                let y = y0 + row;
                let mut previous = [0u8; 4];
                for x in 0..width {
                    let i = row * width + x;
                    let at = (y * width + x) * 4;
                    let mut residual = [0u8; 4];
                    for c in 0..colors {
                        residual[c] = planes[c][i];
                    }
                    if colors >= 3 {
                        residual[0] = residual[0].wrapping_add(residual[1]);
                        residual[2] = residual[2].wrapping_add(residual[1]);
                    }
                    for c in 0..colors {
                        previous[c] = previous[c].wrapping_add(residual[c]);
                        let above = if y == 0 {
                            0
                        } else {
                            pixels[at - width * 4 + c]
                        };
                        pixels[at + c] = previous[c].wrapping_add(above);
                    }
                    if colors == 1 {
                        pixels[at + 1] = pixels[at];
                        pixels[at + 2] = pixels[at];
                    }
                    if colors < 4 {
                        pixels[at + 3] = 255;
                    }
                }
            }
        }
        if r.remaining() != 0 {
            return Err(corrupt("Trailing TLG5 image data"));
        }
        Ok(Image {
            meta,
            pixels: PixelBuffer::Bgra8(pixels),
        })
    }
}
vnlens_core::inventory::submit! {ImageRegistration(||Box::new(Tlg))}

#[cfg(test)]
#[path = "../../tests/krkr/mod.rs"]
mod tests;
