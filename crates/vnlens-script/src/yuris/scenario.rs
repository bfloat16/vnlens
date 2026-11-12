//! ERIS runtime scenario text, loaded by es.SCENARIO.LOAD and tokenized by
//! es.SCENARIO.LEXER. Scenario resources use CP932; commands and message markers
//! remain intact for consumers that understand the game's scenario dialect.

use crate::{ScriptFormat, ScriptRegistration, ir::Script};
use vnlens_core::{Format, ResourceResolver, Result};

#[derive(Debug, Default)]
struct Scenario;

impl Format for Scenario {
    fn tag(&self) -> &'static str {
        "scenario/yuris"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["txt"]
    }
    fn description(&self) -> &'static str {
        "YU-RIS ERIS scenario text"
    }
}

impl ScriptFormat for Scenario {
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        super::expression::text(data, 0).map(Some)
    }
    fn disassemble(&self, _: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        Ok(None)
    }
}

vnlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Scenario)) }

#[cfg(test)]
#[path = "../../tests/yuris/scenario.rs"]
mod tests;
