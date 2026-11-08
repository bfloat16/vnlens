//! GUI-independent pixels and PNG export with pixel offsets retained.
use nvlens_core::{Error, Result};
use nvlens_io::BinaryWriter;
use std::io::Cursor;

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
mod simd;

/// Swaps red and blue channels in complete four-byte pixels; trailing bytes
/// are untouched. Used for BGRA PNG export and GPU preview texture preparation.
pub fn swap_red_blue(bytes: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        simd::swap_red_blue(bytes);
    }
    #[cfg(not(target_arch = "x86_64"))]
    for pixel in bytes.as_chunks_mut::<4>().0 {
        pixel.swap(0, 2);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OffsetUnit {
    #[default]
    Pixels,
    Micrometers,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageMeta {
    pub width: u32,
    pub height: u32,
    pub offset_x: i32,
    pub offset_y: i32,
    pub offset_unit: OffsetUnit,
    pub bpp: u16,
}
impl ImageMeta {
    pub fn rgba_size(&self) -> Result<usize> {
        u64::from(self.width)
            .checked_mul(u64::from(self.height))
            .and_then(|v| v.checked_mul(4))
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(|| Error::Unsupported("Image dimensions exceed address space".into()))
    }
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum PixelBuffer {
    Rgba8(Vec<u8>),
    Bgra8(Vec<u8>),
    Rgba16(Vec<u16>),
}

#[derive(Clone, Debug)]
pub struct Image {
    pub meta: ImageMeta,
    pub pixels: PixelBuffer,
}

impl Image {
    pub fn to_png(&self) -> Result<Vec<u8>> {
        let mut out = Cursor::new(Vec::new());
        match &self.pixels {
            PixelBuffer::Rgba16(words) => {
                let pixels = image::ImageBuffer::<image::Rgba<u16>, _>::from_raw(
                    self.meta.width,
                    self.meta.height,
                    words.clone(),
                )
                .ok_or_else(|| Error::Corrupt {
                    offset: 0,
                    reason: "16-bit pixel buffer does not match dimensions".into(),
                })?;
                image::DynamicImage::ImageRgba16(pixels)
                    .write_to(&mut out, image::ImageFormat::Png)
                    .map_err(|e| Error::Unsupported(format!("PNG encoding failed: {e}")))?;
            }
            PixelBuffer::Rgba8(bytes) | PixelBuffer::Bgra8(bytes) => {
                if bytes.len() != self.meta.rgba_size()? {
                    return Err(Error::Corrupt {
                        offset: 0,
                        reason: "Pixel buffer size does not match dimensions".into(),
                    });
                }
                let rgba = if matches!(self.pixels, PixelBuffer::Bgra8(_)) {
                    let mut bytes = bytes.clone();
                    swap_red_blue(&mut bytes);
                    std::borrow::Cow::Owned(bytes)
                } else {
                    std::borrow::Cow::Borrowed(bytes.as_slice())
                };
                image::write_buffer_with_format(
                    &mut out,
                    &rgba,
                    self.meta.width,
                    self.meta.height,
                    image::ExtendedColorType::Rgba8,
                    image::ImageFormat::Png,
                )
                .map_err(|e| Error::Unsupported(format!("PNG encoding failed: {e}")))?;
            }
        }
        Ok(self.with_offset(out.into_inner()))
    }

    fn with_offset(&self, mut out: Vec<u8>) -> Vec<u8> {
        if self.meta.offset_x != 0
            || self.meta.offset_y != 0
            || self.meta.offset_unit != OffsetUnit::Pixels
        {
            let mut chunk = [0; 21];
            BinaryWriter::u32_be(9, &mut chunk);
            chunk[4..8].copy_from_slice(b"oFFs");
            BinaryWriter::u32_be(self.meta.offset_x as u32, &mut chunk[8..]);
            BinaryWriter::u32_be(self.meta.offset_y as u32, &mut chunk[12..]);
            chunk[16] = match self.meta.offset_unit {
                OffsetUnit::Pixels => 0,
                OffsetUnit::Micrometers => 1,
            };
            let crc = nvlens_crypto::checksum::crc32::ieee(0, &chunk[4..17]);
            BinaryWriter::u32_be(crc, &mut chunk[17..]);
            out.splice(33..33, chunk);
        }
        out
    }
}
