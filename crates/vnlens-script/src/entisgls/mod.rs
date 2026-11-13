//! Cotopha CSX documents: a 64-byte Entis header followed by LE section
//! records. Classic images use the fifteen-handler table in sub_418FB0;
//! ECS images with `header  ` use the thirty-handler table in sub_497720.
//! The complete section bytes are retained alongside decoded instructions.
mod bytecode;

use crate::{ScriptFormat, ScriptRegistration, ir::*};
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{Error, Format, ResourceResolver, Result};
use vnlens_io::BinaryReader;

#[derive(Debug, Default)]
struct Csx;
impl Format for Csx {
    fn tag(&self) -> &'static str {
        "csx/entisgls"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x6974_6e45]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["csx"]
    }
    fn description(&self) -> &'static str {
        "Cotopha compiled script image"
    }
}
impl ScriptFormat for Csx {
    fn disassemble(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
    ) -> Result<Option<Script>> {
        self.disassemble_cancellable(
            data,
            resources,
            &Default::default(),
            &AtomicBool::new(false),
        )
    }
    fn disassemble_cancellable(
        &self,
        data: &[u8],
        _: Option<&dyn ResourceResolver>,
        _: &vnlens_core::ArchiveOptions,
        cancel: &AtomicBool,
    ) -> Result<Option<Script>> {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let mut header = BinaryReader::new(data);
        if header.read_bytes(8)? != b"Entis\x1a\0\0" || header.read_u32_le()? != u32::MAX {
            return Err(bad(0, "Invalid Cotopha image signature"));
        }
        header.read_u32_le()?;
        if !header.read_bytes(48)?.starts_with(b"Cotopha Image file\0") {
            return Err(bad(16, "Invalid Cotopha image description"));
        }
        let source = data;
        let sections = vnlens_middleware::erisa::sections(&source, 64, data.len() as u64 - 64)?;
        let newer = sections.iter().any(|s| s.id == *b"header  ");
        let mut pool = Vec::new();
        if let Some(section) = sections.iter().find(|s| s.id == *b"conststr") {
            let mut r = BinaryReader::new_at(data, section.offset as usize)?;
            let count = r.read_u32_le()?;
            for _ in 0..count {
                if cancel.load(Ordering::Relaxed) {
                    return Err(Error::Cancelled);
                }
                let len = r.read_u32_le()?;
                let raw = r.read_bytes(
                    usize::try_from(u64::from(len) * 2).map_err(std::io::Error::other)?,
                )?;
                pool.push(utf16_bytes(raw)?);
                let refs = r.read_u32_le()?;
                r.read_bytes(usize::try_from(u64::from(refs) * 4).map_err(std::io::Error::other)?)?;
            }
            if r.position() as u64 != section.offset + section.size {
                return Err(bad(
                    r.position() as u64,
                    "Cotopha constant-string table length mismatch",
                ));
            }
        }
        let image = sections
            .iter()
            .find(|s| s.id == *b"image   ")
            .ok_or_else(|| bad(64, "Missing Cotopha code image"))?;
        let bytes = data
            .get(image.offset as usize..(image.offset + image.size) as usize)
            .ok_or_else(|| bad(image.offset, "Invalid Cotopha code range"))?;
        let mut seeds = Vec::new();
        if newer && let Some(section) = sections.iter().find(|s| s.id == *b"funcinfo") {
            let mut reader = BinaryReader::new(
                &data[section.offset as usize..(section.offset + section.size) as usize],
            );
            let count = reader.read_u32_le()?;
            for _ in 0..count {
                if cancel.load(Ordering::Relaxed) {
                    return Err(Error::Cancelled);
                }
                let flags = reader.read_u32_le()?;
                let address = reader.read_u32_le()? as usize;
                let size = reader.read_u32_le()? as usize;
                let extra = reader.read_u32_le()? as usize;
                let name_len = reader.read_u32_le()?;
                reader.read_bytes(
                    usize::try_from(u64::from(name_len) * 2).map_err(std::io::Error::other)?,
                )?;
                reader.read_bytes(extra)?;
                // Native FUNC_ENTRY uses -1 for unresolved addresses and
                // unknown code lengths; class image records are data.
                if size != 0 && flags & 0x10 == 0 && address != u32::MAX as usize {
                    if address >= bytes.len()
                        || (size != u32::MAX as usize && size > bytes.len() - address)
                    {
                        return Err(bad(
                            section.offset,
                            &format!(
                                "Cotopha function range exceeds image: flags 0x{flags:X}, address 0x{address:X}, size 0x{size:X}, image size 0x{:X}",
                                bytes.len()
                            ),
                        ));
                    }
                    seeds.push(address);
                }
            }
        }
        let instructions =
            bytecode::disassemble(bytes, image.offset, &pool, newer, &seeds, cancel)?;
        Ok(Some(Script {
            ir_version: VERSION,
            format: self.tag().into(),
            format_version: u32::from(newer),
            sections: sections
                .iter()
                .map(|s| Section {
                    name: String::from_utf8_lossy(&s.id).trim_end().into(),
                    span: Span {
                        offset: s.offset,
                        size: s.size,
                    },
                    raw: data[s.offset as usize..(s.offset + s.size) as usize].to_vec(),
                })
                .collect(),
            instructions,
        }))
    }
}

pub(super) fn utf16_bytes(bytes: &[u8]) -> Result<Value> {
    let mut r = BinaryReader::new(bytes);
    let mut words = Vec::new();
    while r.remaining() != 0 {
        words.push(r.read_u16_le()?);
    }
    Ok(match String::from_utf16(&words) {
        Ok(text) => Value::Text(text),
        Err(_) => Value::Bytes(bytes.to_vec()),
    })
}
fn bad(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

#[derive(Debug, Default)]
struct Text;
impl Format for Text {
    fn tag(&self) -> &'static str {
        "text/entisgls"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["srcxml", "xml", "inf", "gds", "txt", "ini"]
    }
    fn description(&self) -> &'static str {
        "EntisGLS text and XML source resources"
    }
}
impl ScriptFormat for Text {
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        vnlens_middleware::erisa::text(data).map(Some)
    }
    fn disassemble(&self, _: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        Ok(None)
    }
}
vnlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Csx)) }
vnlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Text)) }

#[cfg(test)]
#[path = "../../tests/entisgls/mod.rs"]
mod tests;
