//! Script-domain registration for middleware readers. Parsing belongs to
//! vnlens-middleware; this adapter preserves the selected script route.
use crate::{ScriptFormat, ScriptRegistration, ir::Script};
use vnlens_core::{Format, ResourceResolver, Result};

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
        vnlens_middleware::lua::disassemble(data).map(Some)
    }
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        if data.starts_with(b"\x1bLua") {
            return Ok(None);
        }
        Ok(std::str::from_utf8(data).ok().map(str::to_owned))
    }
}

vnlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Lua)) }

#[cfg(test)]
#[path = "../tests/middleware.rs"]
mod tests;
