//! Artemis text sources and ASB command blocks. .ast/.ipt/.tbl are Lua source
//! or Lua chunks and use the existing middleware reader through engine routing.
//! IET, INI and SLI are UTF-8 text. ASB decoding follows CArtemisParser::load
//! (sub_1400C9A00), retaining names/values without executing script expressions.
mod asb;

use crate::{ScriptFormat, ScriptRegistration, ir::Script};
use vnlens_core::{Error, Format, ResourceResolver, Result};

#[derive(Debug, Default)]
struct Text;
impl Format for Text {
    fn tag(&self) -> &'static str {
        "text/artemis"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["iet", "ini", "sli"]
    }
    fn description(&self) -> &'static str {
        "Artemis UTF-8 source text"
    }
}
impl ScriptFormat for Text {
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        std::str::from_utf8(data)
            .map(|s| Some(s.to_owned()))
            .map_err(|e| Error::Corrupt {
                offset: e.valid_up_to() as u64,
                reason: "Artemis source text is not UTF-8".into(),
            })
    }
    fn disassemble(&self, _: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        Ok(None)
    }
}
vnlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Text)) }

#[cfg(test)]
#[path = "../../tests/artemis/mod.rs"]
mod tests;
