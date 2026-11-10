//! Modern C,system image records (sub_4AF9E0): b/c contain BE-sized JPEG/PNG;
//! a/d carry a LE base resource ID, flags and separate alpha/mask/RGB planes.
//! sub_4AFBE0 merges raw BGR patches, sub_44CE80 patches a decoded base texture.
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer};
use std::{borrow::Cow, collections::HashSet};
use vnlens_core::{Error, Format, ResourceResolver, Result};
use vnlens_io::{BinaryReader, Endian};
const SIGNATURES: &[u32] = &[0];
mod legacy;
#[derive(Clone, Copy, Debug)]
enum Csystem {
    Modern,
    Legacy,
}
impl Format for Csystem {
    fn tag(&self) -> &'static str {
        match self {
            Self::Modern => "image/csystem",
            Self::Legacy => "image-legacy/csystem",
        }
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["cimg", "b0", "n0", "o0"]
    }
    fn description(&self) -> &'static str {
        "C,system images and referenced texture patches"
    }
}
struct Planes<'a> {
    base: u32,
    width: u32,
    height: u32,
    flags: u32,
    alpha: &'a [u8],
    mask: &'a [u8],
    rgb: &'a [u8],
}
impl Csystem {
    fn planes(self, data: &[u8]) -> Result<Planes<'_>> {
        if matches!(self, Self::Legacy) {
            return legacy::planes(data);
        }
        let mut r = BinaryReader::new_at(data, 1)?;
        let base = r.read_u32_le()?;
        r.read_u32_le()?;
        let width = r.read_u32_le()?;
        let height = r.read_u32_le()?;
        let flags = r.read_u32_le()?;
        let alpha_size = r.read_u32_le()? as usize;
        let alpha = if flags & 4 != 0 {
            r.read_bytes(alpha_size)?
        } else {
            &[]
        };
        let mask_size = r.read_u32_le()? as usize;
        let mask = r.read_bytes(mask_size)?;
        let size = r.read_u32_le()? as usize;
        let rgb = r.read_bytes(size)?;
        Ok(Planes {
            base,
            width,
            height,
            flags,
            alpha,
            mask,
            rgb,
        })
    }
    fn encoded(self, data: &[u8]) -> Result<Option<&[u8]>> {
        if !matches!(data.first(), Some(b'b' | b'c')) {
            return Ok(None);
        }
        let mut r = BinaryReader::new_at(data, 1)?;
        let size = r.read_u32(Endian::Big)? as usize;
        if data[0] == b'c' && matches!(self, Self::Modern) {
            r.read_u8()?;
        }
        Ok(Some(r.read_bytes(size)?))
    }
}
impl ImageFormat for Csystem {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        if let Some(bytes) = self.encoded(data)? {
            return crate::standard::Raster.metadata(bytes);
        }
        if data.first() != Some(&b'a') {
            return Ok(None);
        }
        let p = self.planes(data)?;
        Ok(Some(meta(p.width, p.height)))
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        self.decode_with_resources(data, None)
    }
    fn decode_with_resources(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
    ) -> Result<Image> {
        let mut current = Cow::Borrowed(data);
        let mut patches = Vec::new();
        let mut seen = HashSet::new();
        let mut image = loop {
            if let Some(bytes) = self.encoded(&current)? {
                let mut image = crate::standard::Raster.decode(bytes)?;
                if matches!(self, Self::Legacy) {
                    legacy::flip(&mut image)?;
                }
                break image;
            }
            if !matches!(current.first(), Some(b'a' | b'd')) {
                return Err(Error::InvalidFormat);
            }
            let p = self.planes(&current)?;
            let dependent = matches!(self, Self::Modern) && current[0] == b'd'
                || p.flags & 1 != 0 && !p.mask.is_empty();
            if !dependent {
                if current[0] == b'd' {
                    let mut image = crate::standard::Raster.decode(p.rgb)?;
                    if matches!(self, Self::Legacy) {
                        legacy::flip(&mut image)?;
                    }
                    break image;
                }
                break raw(&p)?;
            }
            if !seen.insert(p.base) {
                return Err(bad("Cyclic C,system base image reference"));
            }
            let name = match self {
                Self::Modern => format!("{:08}.cimg", p.base),
                Self::Legacy => format!("picture/{}.b0", p.base),
            };
            let bytes = resources
                .ok_or_else(|| {
                    Error::Unsupported("C,system image requires its base resource".into())
                })?
                .read_resource(&name)?
                .ok_or_else(|| {
                    Error::Unsupported(format!("C,system base image is missing: {name}"))
                })?;
            patches.push(current.into_owned());
            current = Cow::Owned(bytes);
        };
        if let PixelBuffer::Rgba8(mut bytes) = image.pixels {
            crate::model::swap_red_blue(&mut bytes);
            image.pixels = PixelBuffer::Bgra8(bytes);
        }
        for bytes in patches.iter().rev() {
            let p = self.planes(bytes)?;
            let PixelBuffer::Bgra8(pixels) = &mut image.pixels else {
                return Err(Error::Unsupported(
                    "C,system patch requires 8-bit base pixels".into(),
                ));
            };
            let mut rgb = BinaryReader::new(p.rgb);
            let mut alpha = BinaryReader::new(p.alpha);
            if p.mask.len() < pixels.len().div_ceil(32) {
                return Err(bad("C,system patch mask does not cover its base"));
            }
            for (i, pixel) in pixels.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                if p.mask[i / 8] & (1 << (i % 8)) != 0 {
                    pixel[..3].copy_from_slice(rgb.read_bytes(3)?);
                    if bytes[0] == b'd' {
                        pixel[3] = alpha.read_u8()?;
                    }
                }
            }
            if rgb.remaining() != 0 {
                return Err(bad("C,system patch RGB size disagrees with mask"));
            }
        }
        if matches!(self, Self::Legacy) {
            legacy::flip(&mut image)?;
        }
        Ok(image)
    }
}
fn meta(width: u32, height: u32) -> ImageMeta {
    ImageMeta {
        width,
        height,
        bpp: 32,
        offset_x: 0,
        offset_y: 0,
        offset_unit: OffsetUnit::Pixels,
    }
}
fn raw(p: &Planes<'_>) -> Result<Image> {
    let meta = meta(p.width, p.height);
    let size = meta.rgba_size()?;
    if p.rgb.len() == size / 4 && p.alpha.is_empty() {
        let pixels = p.rgb.iter().flat_map(|&v| [v, v, v, 255]).collect();
        return Ok(Image {
            meta,
            pixels: PixelBuffer::Bgra8(pixels),
        });
    }
    let stride = (u64::from(p.width) * 3 + 3) & !3;
    let required = stride
        .checked_mul(u64::from(p.height))
        .ok_or_else(|| bad("C,system pixel size overflow"))?;
    if required != p.rgb.len() as u64 {
        return Err(bad("C,system RGB plane size disagrees with dimensions"));
    }
    let has_alpha = p.flags & 6 == 6;
    if has_alpha && required != p.alpha.len() as u64 {
        return Err(bad("C,system alpha plane size disagrees with dimensions"));
    }
    let mut out = vec![0; size];
    for y in 0..p.height as usize {
        for x in 0..p.width as usize {
            let src = y * stride as usize + x * 3;
            let dst = (y * p.width as usize + x) * 4;
            out[dst..dst + 3].copy_from_slice(&p.rgb[src..src + 3]);
            out[dst + 3] = if has_alpha { p.alpha[src] } else { 255 };
        }
    }
    Ok(Image {
        meta,
        pixels: PixelBuffer::Bgra8(out),
    })
}
fn bad(reason: &str) -> Error {
    Error::Corrupt {
        offset: 0,
        reason: reason.into(),
    }
}
vnlens_core::inventory::submit! {ImageRegistration(||Box::new(Csystem::Modern))}
vnlens_core::inventory::submit! {ImageRegistration(||Box::new(Csystem::Legacy))}
#[cfg(test)]
#[path = "../../tests/csystem/mod.rs"]
mod tests;
