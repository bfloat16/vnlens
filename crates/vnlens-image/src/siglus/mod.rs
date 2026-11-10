//! G00 image variants, verified against sub_6DDE10, sub_6DDF30, sub_6DE080
//! and sub_6DE100. LE dimensions, per-frame rectangles, one shared LZ stream.
//! Type 0 uses BGR literals; Siglus expands them to BGRA before references.
//! Type 1 uses a BGRA palette. Type 2 stores independent patch lists per frame.
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer};
use vnlens_core::{Error, Format, Result};
use vnlens_io::{BinaryIo, BinaryReader};

#[derive(Debug)]
struct Header {
    kind: u8,
    width: u16,
    height: u16,
    count: u32,
    payload: usize,
}
impl Header {
    fn parse(data: &[u8]) -> Result<Option<Self>> {
        if data.len() < 13 || data[0] > 3 {
            return Ok(None);
        }
        let mut r = BinaryReader::new(data);
        let kind = r.read_u8()?;
        let width = r.read_u16_le()?;
        let height = r.read_u16_le()?;
        if width == 0 || height == 0 {
            return Ok(None);
        }
        let count = if kind == 2 { r.read_u32_le()? } else { 1 };
        let payload = if kind == 2 {
            let size = usize::try_from(u64::from(count) * 24)
                .map_err(|_| corrupt(5, "G00 index exceeds memory"))?;
            if size > r.remaining() {
                return Ok(None);
            }
            r.read_bytes(size)?;
            r.position()
        } else {
            5
        };
        if kind == 3 {
            if data.get(5..7) != Some(&[0xff, 0xd8]) {
                return Ok(None);
            }
        } else {
            let Some(size) = data.get(payload..payload + 4) else {
                return Ok(None);
            };
            if u64::from(BinaryReader::u32_le(size)) + payload as u64 != data.len() as u64 {
                return Ok(None);
            }
        }
        Ok(Some(Self {
            kind,
            width,
            height,
            count,
            payload,
        }))
    }
    fn meta(&self) -> ImageMeta {
        ImageMeta {
            width: u32::from(self.width),
            height: u32::from(self.height),
            offset_x: 0,
            offset_y: 0,
            offset_unit: OffsetUnit::Pixels,
            bpp: 32,
        }
    }
}
fn corrupt(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
fn lz_error(e: std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        Error::Io(e)
    } else {
        corrupt(0, &format!("G00 LZ: {e}"))
    }
}
#[derive(Debug, Default)]
struct G00;
impl Format for G00 {
    fn tag(&self) -> &'static str {
        "g00/siglus"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["g00"]
    }
    fn description(&self) -> &'static str {
        "Siglus/RealLive G00 multi-frame image"
    }
}
impl ImageFormat for G00 {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        Ok(Header::parse(data)?.map(|h| h.meta()))
    }
    fn frame_count(&self, data: &[u8]) -> Result<usize> {
        Ok(Header::parse(data)?.ok_or(Error::InvalidFormat)?.count as usize)
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        self.decode_frame(data, 0)
    }
    fn decode_frame(&self, data: &[u8], frame: usize) -> Result<Image> {
        let h = Header::parse(data)?.ok_or(Error::InvalidFormat)?;
        if frame >= h.count as usize {
            return Err(corrupt(5, "G00 frame index out of range"));
        }
        let meta = h.meta();
        let size = meta.rgba_size()?;
        let pixels = match h.kind {
            0 => {
                let unpacked = BinaryReader::new_at(data, h.payload + 4)?.read_u32_le()? as usize;
                if unpacked == size {
                    vnlens_crypto::compress::siglus::decode_bgr(&data[h.payload..])
                        .map_err(lz_error)?
                } else if unpacked == size / 4 * 3 {
                    let bgr = vnlens_crypto::compress::siglus::decode(&data[h.payload..], 1, 3)
                        .map_err(lz_error)?;
                    let (pixels, _) = bgr.as_chunks::<3>();
                    pixels
                        .iter()
                        .flat_map(|p| [p[0], p[1], p[2], 255])
                        .collect()
                } else {
                    return Err(corrupt(
                        h.payload + 4,
                        "G00 pixel count differs from dimensions",
                    ));
                }
            }
            1 => {
                let decoded = vnlens_crypto::compress::siglus::decode(&data[h.payload..], 2, 1)
                    .map_err(lz_error)?;
                let mut r = BinaryReader::new(&decoded);
                let count = usize::from(r.read_u16_le()?);
                let palette = r.read_bytes(count * 4)?;
                let indices = r.read_bytes(size / 4)?;
                let mut pixels = Vec::with_capacity(size);
                for &index in indices {
                    let at = usize::from(index) * 4;
                    pixels.extend_from_slice(
                        palette
                            .get(at..at + 4)
                            .ok_or_else(|| corrupt(h.payload, "G00 palette index out of range"))?,
                    );
                }
                pixels
            }
            2 => decode_patches(data, &h, frame, size)?,
            3 => {
                let image = crate::standard::Raster.decode(&data[5..])?;
                if image.meta.width != meta.width || image.meta.height != meta.height {
                    return Err(corrupt(1, "G00 JPEG dimensions differ from header"));
                }
                return Ok(image);
            }
            _ => return Err(Error::InvalidFormat),
        };
        Ok(Image {
            meta,
            pixels: PixelBuffer::Bgra8(pixels),
        })
    }
}

fn decode_patches(data: &[u8], h: &Header, frame: usize, size: usize) -> Result<Vec<u8>> {
    let mut region = BinaryReader::new_at(data, 9 + frame * 24)?;
    let origin_x = region.read_u32_le()? as i32;
    let origin_y = region.read_u32_le()? as i32;
    let decoded =
        vnlens_crypto::compress::siglus::decode(&data[h.payload..], 2, 1).map_err(lz_error)?;
    let mut r = BinaryReader::new(&decoded);
    if r.read_u32_le()? != h.count {
        return Err(corrupt(h.payload, "G00 frame counts differ"));
    }
    r.read_bytes(
        usize::try_from(u64::from(h.count) * 8)
            .map_err(|_| corrupt(5, "G00 frame index exceeds memory"))?,
    )?;
    r.set_position(4 + frame * 8)?;
    let offset = r.read_u32_le()? as usize;
    let length = r.read_u32_le()? as usize;
    let mut pixels = vec![0; size];
    if length == 0 {
        return Ok(pixels);
    }
    r.set_position(offset)?;
    let mut body = BinaryReader::new(r.read_bytes(length)?);
    let kind = body.read_u16_le()?;
    if kind != 1 {
        return Err(Error::Unsupported(format!("G00 patch layout {kind}")));
    }
    let count = body.read_u16_le()?;
    body.read_bytes(0x70)?;
    for _ in 0..count {
        let x = i64::from(origin_x) + i64::from(body.read_u16_le()?);
        let y = i64::from(origin_y) + i64::from(body.read_u16_le()?);
        body.read_u16_le()?; // GPU blend flag; stored BGRA pixels are unchanged.
        let width = usize::from(body.read_u16_le()?);
        let height = usize::from(body.read_u16_le()?);
        body.read_bytes(0x52)?;
        let patch = body.read_bytes(
            width
                .checked_mul(height)
                .and_then(|n| n.checked_mul(4))
                .ok_or_else(|| BinaryIo::unexpected_eof("G00 patch size overflow"))?,
        )?;
        // Preserve legal off-canvas patches by clipping the render, not their source.
        for row in 0..height {
            let dest_y = y + row as i64;
            if !(0..i64::from(h.height)).contains(&dest_y) {
                continue;
            }
            let left = x.max(0);
            let right = (x + width as i64).min(i64::from(h.width));
            if right <= left {
                continue;
            }
            let source = (row * width + (left - x) as usize) * 4;
            let dest = (dest_y as usize * usize::from(h.width) + left as usize) * 4;
            let bytes = (right - left) as usize * 4;
            pixels[dest..dest + bytes].copy_from_slice(&patch[source..source + bytes]);
        }
    }
    Ok(pixels)
}
vnlens_core::inventory::submit! { ImageRegistration(||Box::new(G00)) }

#[cfg(test)]
#[path = "../../tests/siglus/mod.rs"]
mod tests;
