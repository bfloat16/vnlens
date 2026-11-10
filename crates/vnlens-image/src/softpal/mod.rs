//! PAL GE method 3 and PGD3 XOR patches. GE has a 32-byte header with LE
//! offsets/dimensions; PGD3 stores a 34-byte CP932 base filename at 14.
//! sub_100C7430 / sub_100B9C20 use PGD LZ and per-row byte predictors.
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer};
use std::collections::HashSet;
use vnlens_core::{Error, Format, ResourceResolver, Result};
use vnlens_io::BinaryReader;
const SIGNATURES: &[u32] = &[0x0020_4547, 0x3344_4750];
#[derive(Debug, Default)]
struct Pgd;
impl Format for Pgd {
    fn tag(&self) -> &'static str {
        "pgd/softpal"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["pgd"]
    }
    fn description(&self) -> &'static str {
        "Softpal GE and PGD3 images"
    }
}
impl ImageFormat for Pgd {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        if data.starts_with(b"GE") {
            let mut r = BinaryReader::new_at(data, 4)?;
            let x = r.read_u32_le()? as i32;
            let y = r.read_u32_le()? as i32;
            let width = r.read_u32_le()?;
            let height = r.read_u32_le()?;
            Ok(Some(ImageMeta {
                width,
                height,
                offset_x: x,
                offset_y: y,
                offset_unit: OffsetUnit::Pixels,
                bpp: 32,
            }))
        } else if data.starts_with(b"PGD3") {
            let mut r = BinaryReader::new_at(data, 4)?;
            let x = r.read_u16_le()?;
            let y = r.read_u16_le()?;
            let width = r.read_u16_le()?;
            let height = r.read_u16_le()?;
            Ok(Some(ImageMeta {
                width: u32::from(width),
                height: u32::from(height),
                offset_x: i32::from(x),
                offset_y: i32::from(y),
                offset_unit: OffsetUnit::Pixels,
                bpp: r.read_u16_le()?,
            }))
        } else {
            Ok(None)
        }
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        self.decode_with_resources(data, None)
    }
    fn decode_with_resources(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
    ) -> Result<Image> {
        let mut patches = Vec::new();
        let mut current = std::borrow::Cow::Borrowed(data);
        let mut seen = HashSet::new();
        while current.starts_with(b"PGD3") {
            let mut r = BinaryReader::new_at(&current, 14)?;
            let name = r
                .read_bytes(34)?
                .split(|b| *b == 0)
                .next()
                .unwrap_or_default();
            let (name, _, errors) = encoding_rs::SHIFT_JIS.decode(name);
            if errors || name.is_empty() {
                return Err(bad(14, "Invalid PGD3 base filename"));
            }
            if !seen.insert(name.replace('\\', "/").to_ascii_lowercase()) {
                return Err(bad(14, "Cyclic PGD3 base reference"));
            }
            let base = resources
                .ok_or_else(|| Error::Unsupported("PGD3 requires its base image".into()))?
                .read_resource(&name)?
                .ok_or_else(|| Error::Unsupported(format!("PGD3 base image is missing: {name}")))?;
            patches.push(current.into_owned());
            current = std::borrow::Cow::Owned(base);
        }
        let mut image = base(&current)?;
        for patch in patches.iter().rev() {
            let meta = self.metadata(patch)?.ok_or(Error::InvalidFormat)?;
            let mut r = BinaryReader::new_at(patch, 48)?;
            let size = r.read_u32_le()? as usize;
            let packed = r.read_u32_le()? as usize;
            let decoded = inflate(r.read_bytes(packed)?, size)?;
            let diff = predict(&decoded, meta.width, meta.height, meta.bpp)?;
            let x = meta.offset_x as u32;
            let y = meta.offset_y as u32;
            if x.checked_add(meta.width)
                .is_none_or(|w| w > image.meta.width)
                || y.checked_add(meta.height)
                    .is_none_or(|h| h > image.meta.height)
            {
                return Err(bad(4, "PGD3 patch exceeds base image"));
            }
            let PixelBuffer::Bgra8(pixels) = &mut image.pixels else {
                return Err(Error::InvalidFormat);
            };
            let channels = usize::from(meta.bpp / 8);
            for row in 0..meta.height as usize {
                let start = ((y as usize + row) * image.meta.width as usize + x as usize) * 4;
                for col in 0..meta.width as usize {
                    for c in 0..channels {
                        pixels[start + col * 4 + c] ^=
                            diff[(row * meta.width as usize + col) * 4 + c];
                    }
                }
            }
        }
        Ok(image)
    }
}
fn base(data: &[u8]) -> Result<Image> {
    if !data.starts_with(b"GE") {
        return Err(Error::InvalidFormat);
    }
    let meta = Pgd.metadata(data)?.ok_or(Error::InvalidFormat)?;
    let mut r = BinaryReader::new_at(data, 2)?;
    let offset = r.read_u16_le()? as usize;
    let mut r = BinaryReader::new_at(data, 28)?;
    let method = r.read_u16_le()?;
    let mut r = BinaryReader::new_at(data, offset)?;
    let size = r.read_u32_le()? as usize;
    let packed = r.read_u32_le()? as usize;
    if method != 3 {
        return Err(Error::Unsupported(format!("Softpal GE method {method}")));
    }
    let decoded = inflate(r.read_bytes(packed)?, size)?;
    let mut r = BinaryReader::new(&decoded);
    r.read_u16_le()?;
    let bpp = r.read_u16_le()?;
    let width = u32::from(r.read_u16_le()?);
    let height = u32::from(r.read_u16_le()?);
    if width != meta.width || height != meta.height {
        return Err(bad(offset, "PGD dimensions disagree"));
    }
    let pixels = predict(r.read_bytes(r.remaining())?, width, height, bpp)?;
    Ok(Image {
        meta,
        pixels: PixelBuffer::Bgra8(pixels),
    })
}
fn inflate(data: &[u8], size: usize) -> Result<Vec<u8>> {
    vnlens_crypto::compress::softpal::decompress(data, size).map_err(|e| match e {
        vnlens_crypto::compress::CompressError::Truncated { pos } => {
            vnlens_io::BinaryIo::unexpected_eof(format!("PGD LZ at {pos}")).into()
        }
        e => bad(0, &format!("PGD LZ: {e}")),
    })
}
fn predict(data: &[u8], width: u32, height: u32, bpp: u16) -> Result<Vec<u8>> {
    if !matches!(bpp, 24 | 32) {
        return Err(Error::Unsupported(format!("PGD bit depth {bpp}")));
    }
    let meta = ImageMeta {
        width,
        height,
        bpp,
        offset_x: 0,
        offset_y: 0,
        offset_unit: OffsetUnit::Pixels,
    };
    if width == 0 || height == 0 {
        return Err(bad(0, "Empty PGD dimensions"));
    }
    let output_size = meta.rgba_size()?;
    let required = (output_size / 4)
        .checked_mul(usize::from(bpp / 8))
        .and_then(|v| v.checked_add(height as usize))
        .ok_or_else(|| bad(0, "PGD predictor size overflow"))?;
    BinaryReader::new(data).read_bytes(required)?;
    let mut out = vec![0u8; output_size];
    let mut r = BinaryReader::new(data);
    let flags = r.read_bytes(height as usize)?;
    let channels = usize::from(bpp / 8);
    let stride = width as usize * 4;
    for (y, &flag) in flags.iter().enumerate() {
        for x in 0..width as usize {
            let at = y * stride + x * 4;
            let mode = if flag & 1 != 0 {
                1
            } else if flag & 2 != 0 {
                2
            } else if flag & 4 != 0 {
                4
            } else {
                0
            };
            if y == 0 && (mode == 2 || mode == 4 && x != 0) {
                return Err(bad(y, "PGD predictor references a missing row"));
            }
            for c in 0..channels {
                let delta = r.read_u8()?;
                let value = match mode {
                    1 if x != 0 => out[at - 4 + c].wrapping_sub(delta),
                    2 => out[at - stride + c].wrapping_sub(delta),
                    4 if x != 0 => (((u16::from(out[at - 4 + c]) + u16::from(out[at - stride + c]))
                        / 2) as u8)
                        .wrapping_sub(delta),
                    _ => delta,
                };
                out[at + c] = value;
            }
            if channels == 3 {
                out[at + 3] = 255;
            }
        }
    }
    Ok(out)
}
fn bad(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
vnlens_core::inventory::submit! { ImageRegistration(|| Box::new(Pgd)) }
#[cfg(test)]
#[path = "../../tests/softpal/mod.rs"]
mod tests;
