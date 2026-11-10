//! Targa images have no fixed magic, so this decoder is explicitly routed by
//! the identified engine's extension. The image crate handles RLE and origin.
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer};
use std::io::Cursor;
use vnlens_core::{Error, Format, Result};
use vnlens_io::BinaryReader;
#[derive(Debug, Default)]
struct Tga;
impl Format for Tga {
    fn tag(&self) -> &'static str {
        "tga"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["tga"]
    }
    fn description(&self) -> &'static str {
        "Targa images"
    }
}
impl ImageFormat for Tga {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        let mut reader =
            image::ImageReader::with_format(Cursor::new(data), image::ImageFormat::Tga);
        reader.no_limits();
        let (width, height) = reader.into_dimensions().map_err(error)?;
        let mut header = BinaryReader::new_at(data, 8)?;
        let offset_x = i32::from(header.read_u16_le()?);
        let offset_y = i32::from(header.read_u16_le()?);
        Ok(Some(ImageMeta {
            width,
            height,
            offset_x,
            offset_y,
            offset_unit: OffsetUnit::Pixels,
            bpp: 32,
        }))
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        let meta = self.metadata(data)?.ok_or(Error::InvalidFormat)?;
        let mut reader =
            image::ImageReader::with_format(Cursor::new(data), image::ImageFormat::Tga);
        reader.no_limits();
        let pixels = reader.decode().map_err(error)?.into_rgba8().into_raw();
        Ok(Image {
            meta,
            pixels: PixelBuffer::Rgba8(pixels),
        })
    }
}
fn error(e: image::ImageError) -> Error {
    Error::Corrupt {
        offset: 0,
        reason: format!("TGA: {e}"),
    }
}
vnlens_core::inventory::submit! { ImageRegistration(|| Box::new(Tga)) }

#[cfg(test)]
#[path = "../tests/tga.rs"]
mod tests;
