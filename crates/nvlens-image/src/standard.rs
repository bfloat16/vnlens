//! Standard raster formats, including PNG files stored directly in YPF.
mod animation;
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer};
use nvlens_core::{Error, Format, Result};
use nvlens_io::BinaryReader;
use std::io::Cursor;

const SIGNATURES: &[u32] = &[0x474e_5089, 0xe0ff_d8ff, 0x3846_4947, 0x0001_0000, 0];
#[derive(Debug, Default)]
pub(crate) struct Raster;
impl Format for Raster {
    fn tag(&self) -> &'static str {
        "image/standard"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["png", "jpg", "jpeg", "bmp", "gif", "webp", "ico"]
    }
    fn description(&self) -> &'static str {
        "PNG, JPEG, BMP, GIF, WebP and ICO"
    }
}
impl ImageFormat for Raster {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        let Ok(format) = image::guess_format(data) else {
            return Ok(None);
        };
        if !matches!(
            format,
            image::ImageFormat::Png
                | image::ImageFormat::Jpeg
                | image::ImageFormat::Bmp
                | image::ImageFormat::Gif
                | image::ImageFormat::WebP
                | image::ImageFormat::Ico
        ) {
            return Ok(None);
        }
        let mut reader = image::ImageReader::with_format(Cursor::new(data), format);
        reader.no_limits();
        let (width, height) = reader.into_dimensions().map_err(error)?;
        let (offset_x, offset_y, offset_unit) = if format == image::ImageFormat::Png {
            png_offset(data)?
        } else {
            (0, 0, OffsetUnit::Pixels)
        };
        Ok(Some(ImageMeta {
            width,
            height,
            offset_x,
            offset_y,
            offset_unit,
            bpp: if format == image::ImageFormat::Png && data.get(24) == Some(&16) {
                64
            } else {
                32
            },
        }))
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        let meta = self.metadata(data)?.ok_or(Error::InvalidFormat)?;
        let mut reader = image::ImageReader::new(Cursor::new(data)).with_guessed_format()?;
        reader.no_limits();
        let decoded = reader.decode().map_err(error)?;
        let pixels = if meta.bpp == 64 {
            PixelBuffer::Rgba16(decoded.into_rgba16().into_raw())
        } else {
            PixelBuffer::Rgba8(decoded.into_rgba8().into_raw())
        };
        Ok(Image { meta, pixels })
    }
    fn frame_count(&self, data: &[u8]) -> Result<usize> {
        animation::count(data)
    }
    fn decode_frame(&self, data: &[u8], frame: usize) -> Result<Image> {
        if let Some(pixels) = animation::decode(data, frame)? {
            let mut meta = self.metadata(data)?.ok_or(Error::InvalidFormat)?;
            meta.bpp = 32;
            return Ok(Image {
                meta,
                pixels: PixelBuffer::Rgba8(pixels),
            });
        }
        if frame != 0 {
            return Err(Error::Unsupported("Image frame is out of range".into()));
        }
        self.decode(data)
    }
}
fn png_offset(data: &[u8]) -> Result<(i32, i32, OffsetUnit)> {
    let mut r = BinaryReader::new_at(data, 8)?;
    while r.remaining() != 0 {
        let length = r.read_u32(nvlens_io::Endian::Big)? as usize;
        let name = r.read_bytes(4)?;
        let body = r.read_bytes(length)?;
        r.read_bytes(4)?;
        if name == b"oFFs" && body.len() == 9 {
            return Ok((
                BinaryReader::u32_be(body) as i32,
                BinaryReader::u32_be(&body[4..]) as i32,
                match body[8] {
                    0 => OffsetUnit::Pixels,
                    1 => OffsetUnit::Micrometers,
                    _ => {
                        return Err(Error::Corrupt {
                            offset: r.position() as u64,
                            reason: "Invalid PNG offset unit".into(),
                        });
                    }
                },
            ));
        }
        if name == b"IDAT" || name == b"IEND" {
            break;
        }
    }
    Ok((0, 0, OffsetUnit::Pixels))
}
fn error(e: image::ImageError) -> Error {
    Error::Corrupt {
        offset: 0,
        reason: format!("Image decoding failed: {e}"),
    }
}
nvlens_core::inventory::submit! {ImageRegistration(||Box::new(Raster))}

#[cfg(test)]
#[path = "../tests/standard.rs"]
mod tests;
