//! Propeller MGR: sub_405080/sub_4054F0 read a u16 frame count, optional
//! u32 absolute frame offsets (omitted for one frame), then per frame a
//! u32 BMP size, u32 LZF size and LZF bytes. sub_4054F0 enables BGRA alpha;
//! sub_424EB0 handles DIB palettes and row orientation.
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer};
use nvlens_core::{Error, Format, Result};
use nvlens_crypto::compress::lzf;
use nvlens_io::BinaryReader;

#[derive(Debug, Default)]
struct Mgr;
impl Format for Mgr {
    fn tag(&self) -> &'static str {
        "image/propeller-mgr"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["mgr"]
    }
    fn description(&self) -> &'static str {
        "Propeller MGR LZF bitmap frames"
    }
}
impl ImageFormat for Mgr {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        // MGR has no signature. Require both a bounded frame descriptor and
        // its decoded BMP header before claiming unrelated resources.
        let Ok((source, size)) = frame(data, 0) else {
            return Ok(None);
        };
        let Ok(header) = lzf::prefix(source, size, 54) else {
            return Ok(None);
        };
        if header.len() < 54 || !header.starts_with(b"BM") {
            return Ok(None);
        }
        bitmap_meta(&header).map(Some)
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        self.decode_frame(data, 0)
    }
    fn frame_count(&self, data: &[u8]) -> Result<usize> {
        let mut r = BinaryReader::new(data);
        let count = usize::from(r.read_u16_le()?);
        if count == 0 {
            return Err(Error::InvalidFormat);
        }
        if count != 1 {
            r.read_bytes(count * 4)?;
        }
        Ok(count)
    }
    fn decode_frame(&self, data: &[u8], index: usize) -> Result<Image> {
        let (source, size) = frame(data, index)?;
        let bytes = lzf::decompress(source, size)?;
        let meta = bitmap_meta(&bytes)?;
        if meta.bpp != 32 || BinaryReader::u32_le(&bytes[30..]) != 0 {
            return crate::standard::Raster.decode(&bytes);
        }
        // BI_RGB 32-bit files carry meaningful alpha in this engine, whereas
        // generic BMP readers may treat the high byte as unused.
        let mut r = BinaryReader::new_at(&bytes, 10)?;
        let offset = usize::try_from(r.read_u32_le()?).map_err(|_| Error::InvalidFormat)?;
        r.set_position(22)?;
        let height = r.read_u32_le()? as i32;
        let size = meta.rgba_size()?;
        let stride =
            usize::try_from(u64::from(meta.width) * 4).map_err(|_| Error::InvalidFormat)?;
        let mut pixels = BinaryReader::new_at(&bytes, offset)?
            .read_bytes(size)?
            .to_vec();
        if height > 0 {
            for row in 0..meta.height as usize / 2 {
                let opposite = meta.height as usize - row - 1;
                let (top, bottom) = pixels.split_at_mut(opposite * stride);
                top[row * stride..(row + 1) * stride].swap_with_slice(&mut bottom[..stride]);
            }
        }
        Ok(Image {
            meta,
            pixels: PixelBuffer::Bgra8(pixels),
        })
    }
}
fn frame(data: &[u8], index: usize) -> Result<(&[u8], usize)> {
    let mut r = BinaryReader::new(data);
    let count = usize::from(r.read_u16_le()?);
    if index >= count {
        return Err(Error::Unsupported("MGR frame index out of range".into()));
    }
    let offset = if count == 1 {
        2
    } else {
        let table = r.read_bytes(count * 4)?;
        usize::try_from(BinaryReader::u32_le(&table[index * 4..]))
            .map_err(|_| Error::InvalidFormat)?
    };
    if offset < r.position() {
        return Err(corrupt(offset, "MGR frame overlaps directory"));
    }
    r.set_position(offset)?;
    let unpacked = usize::try_from(r.read_u32_le()?).map_err(|_| Error::InvalidFormat)?;
    let packed = usize::try_from(r.read_u32_le()?).map_err(|_| Error::InvalidFormat)?;
    Ok((r.read_bytes(packed)?, unpacked))
}
fn bitmap_meta(bytes: &[u8]) -> Result<ImageMeta> {
    let mut r = BinaryReader::new(bytes);
    if r.read_bytes(2)? != b"BM" {
        return Err(Error::InvalidFormat);
    }
    r.set_position(14)?;
    let header = r.read_u32_le()?;
    if header < 40 {
        return Err(Error::Unsupported(format!("MGR DIB header size {header}")));
    }
    let width = r.read_u32_le()? as i32;
    let height = r.read_u32_le()? as i32;
    let planes = r.read_u16_le()?;
    let bpp = r.read_u16_le()?;
    let compression = r.read_u32_le()?;
    if width <= 0 || height == 0 || planes != 1 {
        return Err(corrupt(18, "Invalid MGR bitmap dimensions or planes"));
    }
    if !matches!(bpp, 1 | 4 | 8 | 16 | 24 | 32) || !matches!(compression, 0 | 3) {
        return Err(Error::Unsupported("MGR bitmap pixel format".into()));
    }
    Ok(ImageMeta {
        width: width as u32,
        height: height.unsigned_abs(),
        offset_x: 0,
        offset_y: 0,
        offset_unit: OffsetUnit::Pixels,
        bpp,
    })
}
fn corrupt(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
nvlens_core::inventory::submit! { ImageRegistration(|| Box::new(Mgr)) }

#[cfg(test)]
#[path = "../../tests/propeller/mod.rs"]
mod tests;
