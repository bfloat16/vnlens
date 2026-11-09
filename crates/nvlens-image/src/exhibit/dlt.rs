//! UxDeltaDecoder DLT 0x103: 32-byte LE header followed by palette, key,
//! rectangle-delta, hold and end records. Zero color/index bytes preserve the
//! previous frame. Delta alpha uses 0xfe as its unchanged sentinel.

use super::corrupt;
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, PixelBuffer};
use nvlens_core::{Error, Format, Result};
use nvlens_io::BinaryReader;

#[derive(Debug, Default)]
struct Dlt;
impl Format for Dlt {
    fn tag(&self) -> &'static str {
        "dlt/exhibit"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x103]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["dlt"]
    }
    fn description(&self) -> &'static str {
        "ExHIBIT delta animation"
    }
}
impl ImageFormat for Dlt {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        if data.get(28..32) != Some(b"DLT\0") {
            return Ok(None);
        }
        Ok(Some(Animation::parse(data)?.meta))
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        self.decode_frame(data, 0)
    }
    fn frame_count(&self, data: &[u8]) -> Result<usize> {
        Ok(Animation::parse(data)?
            .records
            .iter()
            .filter(|r| r.flags & 0xf00 != 0xe00)
            .count())
    }
    fn decode_frame(&self, data: &[u8], frame: usize) -> Result<Image> {
        Animation::parse(data)?.decode(frame)
    }
}
nvlens_core::inventory::submit! { ImageRegistration(|| Box::new(Dlt)) }

struct Record<'a> {
    flags: u32,
    rect: [usize; 4],
    colors: &'a [u8],
    alpha: &'a [u8],
}
struct Animation<'a> {
    meta: ImageMeta,
    indexed: bool,
    alpha: bool,
    records: Vec<Record<'a>>,
}
impl<'a> Animation<'a> {
    fn parse(data: &'a [u8]) -> Result<Self> {
        let mut r = BinaryReader::new(data);
        let version = r.read_u32_le()?;
        if version != 0x103 {
            return Err(Error::Unsupported(format!("DLT version {version:#x}")));
        }
        let width = r.read_u32_le()?;
        let height = r.read_u32_le()?;
        let count = r.read_u32_le()?;
        let flags = r.read_u32_le()?;
        let _interval = r.read_u32_le()?;
        let _reserved = r.read_u32_le()?;
        if r.read_u32_le()? != 0x544c44 {
            return Err(Error::InvalidFormat);
        }
        let meta = ImageMeta {
            width,
            height,
            offset_x: 0,
            offset_y: 0,
            offset_unit: crate::OffsetUnit::Pixels,
            bpp: 32,
        };
        if width == 0 || height == 0 {
            return Err(corrupt(4, "Empty DLT image"));
        }
        meta.rgba_size()?;
        let mut records = Vec::new();
        let mut ended = false;
        for index in 0..count {
            let start = r.position();
            let flags = r.read_u32_le()?;
            if flags & 0x8000 != 0 {
                if index + 1 != count {
                    return Err(corrupt(start, "DLT ends before record count"));
                }
                ended = true;
                break;
            }
            if flags & 0xf8 != 0 {
                return Err(Error::Unsupported("DLT record loop control".into()));
            }
            let size = r.read_u32_le()? as usize;
            let rect = if flags & 6 == 0 {
                [
                    r.read_u32_le()? as usize,
                    r.read_u32_le()? as usize,
                    r.read_u32_le()? as usize,
                    r.read_u32_le()? as usize,
                ]
            } else {
                [0, 0, width as usize, height as usize]
            };
            if rect[0] > width as usize
                || rect[2] > width as usize - rect[0]
                || rect[1] > height as usize
                || rect[3] > height as usize - rect[1]
            {
                return Err(corrupt(start, "DLT rectangle exceeds canvas"));
            }
            let alpha = if flags & 0x4000 != 0 {
                r.read_u32_le()? as usize
            } else {
                0
            };
            records.push(Record {
                flags,
                rect,
                colors: r.read_bytes(size)?,
                alpha: r.read_bytes(alpha)?,
            });
        }
        if !ended {
            return Err(corrupt(r.position(), "DLT end record is missing"));
        }
        Ok(Self {
            meta,
            indexed: flags & 0xff00 == 0x800,
            alpha: flags & 2 != 0,
            records,
        })
    }

    fn decode(&self, target: usize) -> Result<Image> {
        let mut pixels = vec![0; self.meta.rgba_size()?];
        if !self.alpha {
            for pixel in pixels.as_chunks_mut::<4>().0 {
                pixel[3] = 255;
            }
        }
        let mut palette = None;
        let mut frame = 0;
        for record in &self.records {
            let kind = (record.flags >> 8) & 15;
            if kind == 14 {
                if record.colors.len() != 1024 {
                    return Err(corrupt(0, "DLT palette must contain 256 colors"));
                }
                palette = Some(record.colors);
                continue;
            }
            if record.flags & 4 == 0 && kind != 1 {
                self.apply(record, kind, palette, &mut pixels)?;
            }
            if frame == target {
                return Ok(Image {
                    meta: self.meta.clone(),
                    pixels: PixelBuffer::Rgba8(pixels),
                });
            }
            frame += 1;
        }
        Err(Error::Unsupported("DLT frame is out of range".into()))
    }

    fn apply(
        &self,
        record: &Record<'_>,
        kind: u32,
        palette: Option<&[u8]>,
        pixels: &mut [u8],
    ) -> Result<()> {
        let [left, top, width, height] = record.rect;
        let pixel_size = if self.indexed { 1 } else { 4 };
        let size = width * height * pixel_size;
        let compressed = match kind {
            0 | 15 => false,
            2 => !(self.indexed && record.flags & 0x1000 != 0),
            13 => true,
            _ => return Err(Error::Unsupported(format!("DLT record kind {kind}"))),
        };
        let color = if compressed {
            nvlens_crypto::compress::exhibit::lzss(record.colors, size)?
        } else {
            if record.colors.len() != size {
                return Err(corrupt(0, "DLT color size differs from rectangle"));
            }
            record.colors.to_vec()
        };
        let alpha = if record.flags & 0x4000 != 0 {
            let size = width * height;
            Some(
                if kind == 0 || kind == 15 || (kind == 2 && record.flags & 0x2000 != 0) {
                    if record.alpha.len() != size {
                        return Err(corrupt(0, "DLT alpha size differs from rectangle"));
                    }
                    record.alpha.to_vec()
                } else {
                    nvlens_crypto::compress::exhibit::lzss(record.alpha, size)?
                },
            )
        } else {
            None
        };
        let flipped = matches!(kind, 13 | 15) || record.flags & 0x10000 != 0;
        for row in 0..height {
            let y = top + if flipped { height - 1 - row } else { row };
            for x in 0..width {
                let source = (row * width + x) * pixel_size;
                let dest = (y * self.meta.width as usize + left + x) * 4;
                let bytes = &color[source..source + pixel_size];
                if bytes.iter().any(|&b| b != 0) {
                    let bgr = if self.indexed {
                        if let Some(palette) = palette {
                            let p = usize::from(bytes[0]) * 4;
                            &palette[p..p + 3]
                        } else {
                            &[bytes[0]; 3]
                        }
                    } else {
                        &bytes[..3]
                    };
                    pixels[dest..dest + 3].copy_from_slice(&[bgr[2], bgr[1], bgr[0]]);
                }
                if let Some(alpha) = &alpha {
                    let a = alpha[row * width + x];
                    let unchanged = if kind == 2 { 254 } else { 0 };
                    if a != unchanged {
                        pixels[dest + 3] = a;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/exhibit/dlt.rs"]
mod tests;
