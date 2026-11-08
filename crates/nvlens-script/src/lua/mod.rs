//! Lua middleware, adapted from unluac_rs 0.2.0 for read-only disassembly.
//! Binary parsing, instruction decoding and IR conversion stay private.

use crate::{ScriptFormat, ScriptRegistration, ir::Script};
use nvlens_core::{Error, Format, ResourceResolver, Result};
mod chunk;
mod decode;
mod disasm;
mod instruction;
mod opcode;
mod read;

fn corrupt(offset: usize, reason: impl Into<String>) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}

#[derive(Debug, Default)]
struct Lua;
impl Format for Lua {
    fn tag(&self) -> &'static str {
        "lua"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x6175_4c1b]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["lua", "luac"]
    }
    fn description(&self) -> &'static str {
        "Lua bytecode"
    }
}
impl ScriptFormat for Lua {
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        if !data.starts_with(b"\x1bLua") {
            return Ok(None);
        }
        disasm::parse(data).map(Some)
    }
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        if data.starts_with(b"\x1bLua") {
            return Ok(None);
        }
        Ok(std::str::from_utf8(data).ok().map(str::to_owned))
    }
}
nvlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Lua)) }
