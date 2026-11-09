//! rUGP standalone image objects. Cr6Ti metadata follows rvmm::Serialize at
//! 10073E00; its LSB pixel codec follows 10071E70/rvmm_276. Native object
//! framing is kept separate from the image body and uses the shared name
//! decompressor. All decoding is scalar and bounded by the encoded geometry.
mod r6ti;
mod rsi;
use crate::{Image, ImageFormat, ImageMeta, ImageRegistration, OffsetUnit, PixelBuffer};
use nvlens_core::{Error, Format, Result};
use nvlens_io::BinaryReader;

fn bad(at: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: at as u64,
        reason: reason.into(),
    }
}

fn header(data: &[u8]) -> Result<Option<(String, u16, usize)>> {
    if data.len() < 4 {
        return Ok(None);
    }
    let signature = BinaryReader::u32_le(data);
    if !matches!(signature, 0x29f6cba4 | 0x1edb927c) {
        return Ok(None);
    }
    let mut r = BinaryReader::new(data);
    r.read_u32_le()?;
    let version = r.read_u16_le()?;
    if (0x10..=0x3fff).contains(&version) {
        if version >= 0x11 {
            r.read_u16_le()?;
        }
    } else {
        r.set_position(4)?;
    }
    if r.read_u16_le()? != 0xffff {
        return Err(bad(
            r.position(),
            "Standalone RIO image has no class definition",
        ));
    }
    let schema = r.read_u16_le()?;
    let bytes = if signature == 0x1edb927c {
        let n = r.read_u8()?;
        let n = if n == 255 {
            usize::from(r.read_u16_le()?)
        } else {
            usize::from(n)
        };
        nvlens_crypto::compress::rugp::class_name(r.read_bytes(n)?)?
    } else {
        let n = usize::from(r.read_u16_le()?);
        r.read_bytes(n)?.to_vec()
    };
    let Ok(name) = String::from_utf8(bytes) else {
        return Ok(None);
    };
    if !matches!(
        name.as_str(),
        "Cr6Ti" | "Cr6Tix" | "CRmti" | "CS5i" | "CSbm" | "CIcon"
    ) {
        return Ok(None);
    }
    if signature == 0x1edb927c && r.read_u16_le()? != 0 {
        return Err(Error::Unsupported("RIO image with a child index".into()));
    }
    Ok(Some((name, schema, r.position())))
}

#[derive(Debug)]
struct Meta {
    meta: ImageMeta,
    body: usize,
    schema: u16,
    name: String,
}
fn metadata(data: &[u8]) -> Result<Option<Meta>> {
    let Some((mut name, schema, mut body)) = header(data)? else {
        return Ok(None);
    };
    let mut r = BinaryReader::new_at(data, body)?;
    if name == "Cr6Tix" {
        r.read_u8()?;
        let mut count = u32::from(r.read_u16_le()?);
        if count == 65535 {
            count = r.read_u32_le()?;
        }
        for _ in 0..count {
            r.read_mfc_string()?;
            r.read_u32_le()?;
        }
        body = r.position();
        name = "Cr6Ti".into();
    }
    let meta = if name == "CRmti" {
        let width = u32::from(r.read_u16_le()?);
        let height = u32::from(r.read_u16_le()?);
        ImageMeta {
            width,
            height,
            offset_x: 0,
            offset_y: 0,
            offset_unit: OffsetUnit::Pixels,
            bpp: 32,
        }
    } else if name == "Cr6Ti" {
        r6ti::metadata(&mut r)?
    } else if name == "CS5i" {
        r.read_u32_le()?;
        let offset_x = i32::from(r.read_u16_le()? as i16);
        let offset_y = i32::from(r.read_u16_le()? as i16);
        let width = u32::from(r.read_u16_le()?);
        let height = u32::from(r.read_u16_le()?);
        ImageMeta {
            width,
            height,
            offset_x,
            offset_y,
            offset_unit: OffsetUnit::Pixels,
            bpp: 32,
        }
    } else {
        r.read_u32_le()?;
        let width = u32::from(r.read_u16_le()?);
        let height = u32::from(r.read_u16_le()?);
        ImageMeta {
            width,
            height,
            offset_x: 0,
            offset_y: 0,
            offset_unit: OffsetUnit::Pixels,
            bpp: 32,
        }
    };
    Ok(Some(Meta {
        meta,
        body,
        schema,
        name,
    }))
}

#[derive(Debug, Default)]
struct Rugp;
impl Format for Rugp {
    fn tag(&self) -> &'static str {
        "image/rugp"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x29f6cba4, 0x1edb927c]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["cr6ti", "cs5i", "csbm", "cicon"]
    }
    fn description(&self) -> &'static str {
        "rUGP native image objects"
    }
}
impl ImageFormat for Rugp {
    fn metadata(&self, data: &[u8]) -> Result<Option<ImageMeta>> {
        Ok(metadata(data)?.map(|m| m.meta))
    }
    fn decode(&self, data: &[u8]) -> Result<Image> {
        let m = metadata(data)?.ok_or(Error::InvalidFormat)?;
        if matches!(m.name.as_str(), "Cr6Ti" | "CRmti") {
            return r6ti::decode(data, &m);
        }
        let mut r = BinaryReader::new_at(data, m.body + if m.name == "CS5i" { 20 } else { 12 })?;
        let length = r.read_u32_le()? as usize;
        let pixels = r.read_bytes(length)?;
        if length != m.meta.rgba_size()? {
            return Err(bad(r.position(), "RIO bitmap size differs from dimensions"));
        }
        Ok(Image {
            meta: m.meta,
            pixels: PixelBuffer::Bgra8(pixels.to_vec()),
        })
    }
}
nvlens_core::inventory::submit! {ImageRegistration(||Box::new(Rugp))}

#[cfg(test)]
#[path = "../../tests/rugp/mod.rs"]
mod tests;
