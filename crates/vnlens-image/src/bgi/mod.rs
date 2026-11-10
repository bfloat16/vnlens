//! BGI image dispatch. Raw bitmap headers contain u16 dimensions, bit depth
//! and transform followed by reserved fields. CompressedBG___ adds encrypted
//! metadata and v1 lossless or v2 DCT-coded pixels.
mod cbg;
mod dct;
mod raw;
// Fixed-size SSE2 kernels isolate pointer operations from format parsing.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
mod simd;
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, PixelBuffer};
use vnlens_core::{Error, Format, Result};
#[derive(Debug, Default)]
struct BgiImage;
impl Format for BgiImage {
    fn tag(&self) -> &'static str {
        "image/bgi"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x706d_6f43, 0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["bgi", "bg", "_bg"]
    }
    fn description(&self) -> &'static str {
        "BGI bitmap and CompressedBG v1/v2"
    }
}
impl ImageFormat for BgiImage {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        if data.starts_with(b"CompressedBG___\0") {
            return Ok(Some(cbg::Header::parse(data)?.meta));
        }
        raw::metadata(data)
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        let result = if data.starts_with(b"CompressedBG___\0") {
            cbg::decode(data)
        } else {
            raw::decode(data)
        };
        result.map_err(|error| match error {
            Error::Io(source) if source.kind() == std::io::ErrorKind::InvalidData => {
                corrupt(0, &format!("BGI compression: {source}"))
            }
            error => error,
        })
    }
}
vnlens_core::inventory::submit! { ImageRegistration(|| Box::new(BgiImage)) }
fn corrupt(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
fn from_bgr(meta: ImageMeta, bytes: &[u8]) -> Result<Image> {
    let mut rgba = Vec::with_capacity(meta.rgba_size()?);
    for pixel in bytes.chunks_exact(usize::from(meta.bpp / 8)) {
        match meta.bpp {
            8 => rgba.extend([pixel[0], pixel[0], pixel[0], 255]),
            24 => rgba.extend([pixel[2], pixel[1], pixel[0], 255]),
            32 => rgba.extend([pixel[2], pixel[1], pixel[0], pixel[3]]),
            _ => {
                return Err(Error::Unsupported(format!(
                    "BGI image bit depth {}",
                    meta.bpp
                )));
            }
        }
    }
    Ok(Image {
        meta,
        pixels: PixelBuffer::Rgba8(rgba),
    })
}
