//! PDT10/PDT11: 32-byte LE header, BGR or palette-index color stream,
//! optional separate alpha plane. Layout and color transforms follow
//! GARbro's PdtFormat/PdtReader; both planes retain the full canvas.
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer};
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{Error, Format, Result};
use vnlens_io::BinaryReader;

#[derive(Debug, Default)]
struct Pdt;
impl Format for Pdt {
    fn tag(&self) -> &'static str {
        "pdt/reallive"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x3154_4450]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["pdt"]
    }
    fn description(&self) -> &'static str {
        "RealLive PDT image"
    }
}
#[derive(Debug)]
struct Header {
    version: u8,
    size: usize,
    meta: ImageMeta,
    alpha: usize,
}
fn corrupt(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
fn read(data: &[u8]) -> Result<Header> {
    let mut r = BinaryReader::new(data);
    let signature = r.read_bytes(8)?;
    let version = if signature.starts_with(b"PDT10") {
        0
    } else if signature.starts_with(b"PDT11") {
        1
    } else {
        return Err(Error::InvalidFormat);
    };
    let size = r.read_u32_le()? as usize;
    let width = r.read_u32_le()?;
    let height = r.read_u32_le()?;
    r.read_bytes(8)?;
    let alpha = r.read_u32_le()? as usize;
    if size < 32 || (alpha != 0 && !(32..size).contains(&alpha)) {
        return Err(corrupt(8, "Invalid PDT storage extent"));
    }
    BinaryReader::new(data).read_bytes(size)?;
    let meta = ImageMeta {
        width,
        height,
        offset_x: 0,
        offset_y: 0,
        offset_unit: OffsetUnit::Pixels,
        bpp: 32,
    };
    meta.rgba_size()?;
    Ok(Header {
        version,
        size,
        meta,
        alpha,
    })
}
fn error(e: std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::Interrupted {
        Error::Cancelled
    } else if e.kind() == std::io::ErrorKind::UnexpectedEof {
        Error::Io(e)
    } else {
        corrupt(32, &format!("PDT: {e}"))
    }
}
impl ImageFormat for Pdt {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        read(data).map(|h| Some(h.meta))
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        decode(data, None)
    }
    fn decode_with_options(
        &self,
        data: &[u8],
        _: Option<&dyn vnlens_core::ResourceResolver>,
        _: &vnlens_core::ArchiveOptions,
        cancelled: Option<&AtomicBool>,
    ) -> Result<Image> {
        decode(data, cancelled)
    }
}
fn check(cancelled: Option<&AtomicBool>) -> Result<()> {
    if cancelled.is_some_and(|c| c.load(Ordering::Relaxed)) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
fn decode(data: &[u8], cancelled: Option<&AtomicBool>) -> Result<Image> {
    check(cancelled)?;
    let h = read(data)?;
    let count = h.meta.rgba_size()? / 4;
    let end = if h.alpha == 0 { h.size } else { h.alpha };
    let color = &data[32..end];
    let mut pixels = if h.version == 0 {
        vnlens_crypto::compress::pdt::colors(color, count, cancelled).map_err(error)?
    } else {
        let mut r = BinaryReader::new(color);
        let palette = r.read_bytes(256 * 4)?;
        let mut distances = [0; 16];
        for distance in &mut distances {
            *distance = r.read_u32_le()?;
        }
        let indices = vnlens_crypto::compress::pdt::indices(
            r.read_bytes(r.remaining())?,
            count,
            &distances,
            cancelled,
        )
        .map_err(error)?;
        let mut pixels = Vec::new();
        for index in indices {
            check(cancelled)?;
            let at = usize::from(index) * 4;
            pixels.extend([palette[at], palette[at + 1], palette[at + 2], 255]);
        }
        pixels
    };
    if h.alpha != 0 {
        let alpha = vnlens_crypto::compress::pdt::alpha(&data[h.alpha..h.size], count, cancelled)
            .map_err(error)?;
        for (pixel, value) in pixels.as_chunks_mut::<4>().0.iter_mut().zip(alpha) {
            check(cancelled)?;
            pixel[3] = value;
        }
    }
    Ok(Image {
        meta: h.meta,
        pixels: PixelBuffer::Bgra8(pixels),
    })
}
vnlens_core::inventory::submit! {ImageRegistration(||Box::new(Pdt))}

#[cfg(test)]
#[path = "../../tests/reallive/mod.rs"]
mod tests;
