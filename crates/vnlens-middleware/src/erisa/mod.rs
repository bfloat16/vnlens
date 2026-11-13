//! ERISA raster, sound and movie framing. 64-byte file header, followed by
//! eight-byte section names and LE u64 body lengths. Shared between ERI,
//! MIO and MEI consumers; no engine identity or filesystem scanning.
mod image;
mod lossy;
mod raster;
mod sound;

use image::decode_frame;
pub use raster::RasterDecoder;
pub use sound::{SoundChunk, SoundDecoder, SoundInfo, sound_chunks};
use std::{collections::BTreeMap, io};
use vnlens_core::{Error, Result};
use vnlens_io::{BinaryIo, BinaryReader, ReadAt};

#[derive(Clone, Debug)]
pub struct Section {
    pub id: [u8; 8],
    pub offset: u64,
    pub size: u64,
}

pub fn sections(source: &dyn ReadAt, start: u64, size: u64) -> Result<Vec<Section>> {
    let end = start
        .checked_add(size)
        .filter(|&v| v <= source.len())
        .ok_or_else(|| BinaryIo::unexpected_eof("ERISA section range exceeds source"))?;
    let mut at = start;
    let mut result = Vec::new();
    while at < end {
        if end - at < 16 {
            return Err(BinaryIo::unexpected_eof("Truncated ERISA section header").into());
        }
        let bytes = source.read_at(at, 16)?;
        let mut r = BinaryReader::new(&bytes);
        let mut id = [0; 8];
        id.copy_from_slice(r.read_bytes(8)?);
        let size = r.read_u64_le()?;
        let offset = at + 16;
        at = offset
            .checked_add(size)
            .filter(|&v| v <= end)
            .ok_or_else(|| BinaryIo::unexpected_eof("ERISA section body exceeds parent"))?;
        result.push(Section { id, offset, size });
    }
    Ok(result)
}

#[derive(Clone, Debug)]
pub struct ImageInfo {
    pub transformation: u32,
    pub architecture: i32,
    pub format: u32,
    pub width: u32,
    pub height: u32,
    pub top_down: bool,
    pub bpp: u32,
    pub sampling: u32,
    pub blocking_degree: u32,
}

pub struct MediaFile {
    pub description: String,
    pub milliseconds: u32,
    pub image: Option<ImageInfo>,
    pub tags: BTreeMap<String, String>,
    pub header: Vec<Section>,
    pub stream: Vec<Section>,
}

impl std::fmt::Debug for MediaFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaFile")
            .field("description", &self.description)
            .field("image", &self.image)
            .field("stream", &self.stream)
            .finish_non_exhaustive()
    }
}

impl MediaFile {
    pub fn open(source: &dyn ReadAt) -> Result<Self> {
        let raw = source.read_at(0, 64)?;
        let head = raw.as_ref();
        if !(head.starts_with(b"Entis\x1a\0\0") || head.starts_with(b"VIST\x1a\0\0\0")) {
            return Err(bad(0, "Invalid ERISA media signature"));
        }
        let identity = BinaryReader::u32_le(&head[8..12]);
        if !matches!(identity, 0x0200_0100 | 0x0300_0100) {
            return Err(Error::Unsupported(format!(
                "ERISA media identity 0x{identity:08X}"
            )));
        }
        let description =
            std::str::from_utf8(head[16..48].split(|&b| b == 0).next().unwrap_or_default())
                .map_err(|_| bad(16, "Invalid ERISA description"))?
                .to_owned();
        let top = sections(source, 64, source.len() - 64)?;
        let mut result = Self {
            description,
            milliseconds: 0,
            image: None,
            tags: BTreeMap::new(),
            header: Vec::new(),
            stream: Vec::new(),
        };
        for section in top {
            match &section.id {
                b"Header  " => {
                    result.header = sections(source, section.offset, section.size)?;
                    for h in &result.header {
                        match &h.id {
                            b"FileHdr " => {
                                let bytes = source.read_at(
                                    h.offset,
                                    usize::try_from(h.size).map_err(io::Error::other)?,
                                )?;
                                let mut r = BinaryReader::new(&bytes);
                                if r.read_u32_le()? > 0x20100 {
                                    return Err(Error::Unsupported(
                                        "ERISA file header version".into(),
                                    ));
                                }
                                r.read_bytes(12)?;
                                result.milliseconds = r.read_u32_le()?;
                            }
                            b"ImageInf" => {
                                let bytes = source.read_at(
                                    h.offset,
                                    usize::try_from(h.size).map_err(io::Error::other)?,
                                )?;
                                let mut r = BinaryReader::new(&bytes);
                                let version = r.read_u32_le()?;
                                if !matches!(version, 0x20100 | 0x20200 | 0x20300) {
                                    return Err(Error::Unsupported(format!(
                                        "ERISA image version 0x{version:X}"
                                    )));
                                }
                                let transformation = r.read_u32_le()?;
                                let architecture = r.read_u32_le()? as i32;
                                let format = r.read_u32_le()?;
                                let width = r.read_u32_le()? as i32;
                                let height = r.read_u32_le()? as i32;
                                let bpp = r.read_u32_le()?;
                                if width == 0 || height == 0 {
                                    return Err(bad(h.offset + 16, "Empty ERISA image dimensions"));
                                }
                                r.read_u32_le()?;
                                let sampling = r.read_u32_le()?;
                                r.read_bytes(16)?;
                                let blocking_degree = r.read_u32_le()?;
                                r.read_bytes(12)?;
                                result.image = Some(ImageInfo {
                                    transformation,
                                    architecture,
                                    format,
                                    width: width.unsigned_abs(),
                                    height: height.unsigned_abs(),
                                    top_down: height < 0,
                                    bpp,
                                    sampling,
                                    blocking_degree,
                                });
                            }
                            b"descript" => {
                                let bytes = source.read_at(
                                    h.offset,
                                    usize::try_from(h.size).map_err(io::Error::other)?,
                                )?;
                                result.tags = parse_tags(&text(&bytes)?);
                            }
                            _ => {}
                        }
                    }
                }
                b"Stream  " => {
                    result
                        .stream
                        .extend(sections(source, section.offset, section.size)?)
                }
                _ => {}
            }
        }
        Ok(result)
    }
}

pub fn text(bytes: &[u8]) -> Result<String> {
    if bytes.starts_with(b"\xff\xfe") {
        let mut r = BinaryReader::new(&bytes[2..]);
        let mut words = Vec::new();
        while r.remaining() != 0 {
            words.push(r.read_u16_le()?);
        }
        String::from_utf16(&words).map_err(|_| bad(0, "Invalid ERISA UTF-16 text"))
    } else if bytes.starts_with(b"\xef\xbb\xbf") || std::str::from_utf8(bytes).is_ok() {
        std::str::from_utf8(bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes))
            .map(str::to_owned)
            .map_err(|_| bad(0, "Invalid ERISA UTF-8 text"))
    } else {
        let (value, _, errors) = encoding_rs::SHIFT_JIS.decode(bytes);
        if errors {
            return Err(bad(0, "Invalid ERISA CP932 text"));
        }
        Ok(value.into_owned())
    }
}

fn parse_tags(value: &str) -> BTreeMap<String, String> {
    let mut tags = BTreeMap::new();
    let mut name = String::new();
    for line in value.lines() {
        if let Some(tag) = line.trim_start().strip_prefix('#')
            && !tag.starts_with('#')
        {
            name = tag.trim().to_owned();
            tags.entry(name.clone()).or_insert_with(String::new);
        } else if let Some(value) = tags.get_mut(&name) {
            if !value.is_empty() {
                value.push('\n');
            }
            value.push_str(line.strip_prefix("##").map_or(line, |s| s));
        }
    }
    tags
}

pub(super) fn bad(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "../../tests/erisa/mod.rs"]
mod tests;
