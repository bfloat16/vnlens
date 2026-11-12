//! Kaleido ADV Workshop: Squirrel 2.2.4 closures and text scripts.
use crate::{ScriptFormat, ScriptRegistration, ir::Script};
use vnlens_core::{Format, ResourceResolver, Result};
#[derive(Debug, Default)]
struct Kaleido;
const SIGNATURES: &[u32] = &[0x4952_fafa];
impl Format for Kaleido {
    fn tag(&self) -> &'static str {
        "script/kaleido"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["nut", "cnut", "ks", "scn"]
    }
    fn description(&self) -> &'static str {
        "Kaleido Squirrel bytecode and text scripts"
    }
}
impl ScriptFormat for Kaleido {
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        if data.starts_with(&[0xfa, 0xfa]) {
            vnlens_middleware::squirrel::disassemble(data).map(Some)
        } else {
            Ok(None)
        }
    }
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        if data.starts_with(&[0xfa, 0xfa]) || data.contains(&0) {
            return Ok(None);
        }
        Ok(std::str::from_utf8(data)
            .ok()
            .map(|text| text.trim_start_matches('\u{feff}').to_owned()))
    }
}
vnlens_core::inventory::submit! {ScriptRegistration(||Box::new(Kaleido))}
