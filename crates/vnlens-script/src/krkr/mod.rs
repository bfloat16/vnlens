//! KiriKiri TJS2 bytecode and FE FE encoded text. PSB containers are opened
//! through the archive domain, retaining their metadata and binary resources.
mod bytecode;
mod names;
mod object;
mod opcode;
mod operands;
mod text;
use crate::{ScriptFormat, ScriptRegistration, ir::Script};
pub use names::{name_candidates, psb_name_candidates};
use vnlens_core::{Format, ResourceResolver, Result};
#[derive(Debug, Default)]
struct Tjs;
impl Format for Tjs {
    fn tag(&self) -> &'static str {
        "script/krkr"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x32534a54, 0xff00fefe, 0xff01fefe, 0xff02fefe]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["tjs", "ks"]
    }
    fn description(&self) -> &'static str {
        "KiriKiri TJS2 bytecode and encoded text"
    }
}
impl ScriptFormat for Tjs {
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        if !data.starts_with(b"TJS2") {
            return Ok(None);
        }
        bytecode::parse(data).map(Some)
    }
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        text::decode(data)
    }
}
vnlens_core::inventory::submit! {ScriptRegistration(||Box::new(Tjs))}

fn bad(offset: usize, reason: &str) -> vnlens_core::Error {
    vnlens_core::Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
