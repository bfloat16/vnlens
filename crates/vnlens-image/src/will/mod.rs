//! AdvHD CPNAReader: 20-byte LE header, 40-byte layer records and consecutive
//! PNG payloads. Group markers and empty layers carry no image. PNAP colors
//! are premultiplied; PNAS stores straight colors. MOS may use this container
//! or an ordinary PNG. Layout also documented by GARbro's Will/ArcPNA.cs.

use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer};
use vnlens_core::{Error, Format, Result};
use vnlens_io::BinaryReader;

#[derive(Debug, Default)]
struct Pna;
impl Format for Pna {
    fn tag(&self) -> &'static str {
        "pna/will"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x5041_4e50, 0x5341_4e50]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["pna", "mos"]
    }
    fn description(&self) -> &'static str {
        "AdvHD PNG layer collection"
    }
}
impl ImageFormat for Pna {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        if !(data.starts_with(b"PNAP") || data.starts_with(b"PNAS")) {
            return Ok(None);
        }
        Ok(Some(layer(data, 0)?.0))
    }
    fn frame_count(&self, data: &[u8]) -> Result<usize> {
        Ok(layers(data)?.len())
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        self.decode_frame(data, 0)
    }
    fn decode_frame(&self, data: &[u8], frame: usize) -> Result<Image> {
        let (meta, payload) = layer(data, frame)?;
        if !payload.starts_with(b"\x89PNG\r\n\x1a\n") {
            return Err(Error::InvalidFormat);
        }
        let mut image = crate::standard::Raster.decode(payload)?;
        if image.meta.width != meta.width || image.meta.height != meta.height {
            return Err(corrupt(0, "PNA dimensions differ from embedded PNG"));
        }
        if data.starts_with(b"PNAP") {
            match &mut image.pixels {
                PixelBuffer::Rgba8(bytes) => {
                    for p in bytes.as_chunks_mut::<4>().0 {
                        if p[3] != 0 && p[3] != 255 {
                            for i in 0..3 {
                                p[i] = (u16::from(p[i]) * 255 / u16::from(p[3])).min(255) as u8;
                            }
                        }
                    }
                }
                _ => return Err(Error::Unsupported("PNA requires 8-bit PNG channels".into())),
            }
        }
        image.meta = meta;
        Ok(image)
    }
}
vnlens_core::inventory::submit! { ImageRegistration(|| Box::new(Pna)) }

fn layer(data: &[u8], frame: usize) -> Result<(ImageMeta, &[u8])> {
    layers(data)?
        .into_iter()
        .nth(frame)
        .ok_or_else(|| Error::Unsupported("PNA frame is out of range".into()))
}
fn layers(data: &[u8]) -> Result<Vec<(ImageMeta, &[u8])>> {
    let mut r = BinaryReader::new(data);
    if !matches!(r.read_u32_le()?, 0x5041_4e50 | 0x5341_4e50) {
        return Err(Error::InvalidFormat);
    }
    r.read_bytes(12)?;
    let count = r.read_u32_le()? as usize;
    let table_size = count
        .checked_mul(40)
        .ok_or_else(|| corrupt(16, "PNA table size overflow"))?;
    let table = r.read_bytes(table_size)?;
    let mut table = BinaryReader::new(table);
    let mut layers = Vec::new();
    for _ in 0..count {
        table.read_bytes(8)?;
        let x = table.read_u32_le()? as i32;
        let y = table.read_u32_le()? as i32;
        let width = table.read_u32_le()?;
        let height = table.read_u32_le()?;
        table.read_bytes(12)?;
        let size = table.read_u32_le()? as usize;
        let payload = r.read_bytes(size)?;
        if size == 0 {
            continue;
        }
        if width == 0 || height == 0 {
            return Err(corrupt(r.position(), "PNA image has empty dimensions"));
        }
        let meta = ImageMeta {
            width,
            height,
            offset_x: x,
            offset_y: y,
            offset_unit: OffsetUnit::Pixels,
            bpp: 32,
        };
        meta.rgba_size()?;
        layers.push((meta, payload));
    }
    Ok(layers)
}
fn corrupt(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "../../tests/will/mod.rs"]
mod tests;
