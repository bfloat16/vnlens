//! ExHIBIT RLD v0-v3, verified against RetouchSystem::loadRld/liteLoad and
//! CMD_DATA reader. LE command words encode ID:u16, integer count:u8,
//! string count:4 bits, variant:4 bits. Strings are zero-terminated CP932.
//! Version 1+ adds a u32 and a 256-byte companion-name field to the header.

mod opcode;
mod rld;
mod text;
use crate::{ScriptFormat, ScriptRegistration, ir::Script};
use std::borrow::Cow;
use vnlens_core::{ArchiveOptions, Format, ResourceResolver, Result};

#[derive(Debug, Default)]
struct Rld;
impl Format for Rld {
    fn tag(&self) -> &'static str {
        "rld/exhibit"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x524c_4400]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["rld", "rnf", "ini"]
    }
    fn description(&self) -> &'static str {
        "ExHIBIT RLD bytecode and CP932 configuration text"
    }
}
impl ScriptFormat for Rld {
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        text::decode(data)
    }
    fn decode<'a>(&self, data: &'a [u8], options: &ArchiveOptions) -> Result<Cow<'a, [u8]>> {
        rld::decode(data, options)
    }
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        if !data.starts_with(b"\0DLR") {
            return Ok(None);
        }
        rld::parse(data).map(Some)
    }
}
vnlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Rld)) }
