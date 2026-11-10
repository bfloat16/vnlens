//! Kaleido ADV Workshop: Squirrel 2.2.4 closures and PSB scenario trees.
mod squirrel;
use crate::{ScriptContent, ScriptFormat, ScriptRegistration, ir::Script};
use nvlens_core::{Format, ResourceResolver, Result};
#[derive(Debug, Default)]
struct Kaleido;
const SIGNATURES: &[u32] = &[0x4952_fafa, 0x0042_5350, 0x0073_7a6d, 0x0066_646d];
impl Format for Kaleido {
    fn tag(&self) -> &'static str {
        "script/kaleido"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["nut", "cnut", "ks", "scn", "psb"]
    }
    fn description(&self) -> &'static str {
        "Kaleido Squirrel bytecode and PSB scenarios"
    }
}
impl ScriptFormat for Kaleido {
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        if data.starts_with(&[0xfa, 0xfa]) {
            squirrel::parse(data).map(Some)
        } else {
            Ok(None)
        }
    }
    fn decode_content(&self, data: &[u8]) -> Result<Option<ScriptContent>> {
        if data.starts_with(b"PSB\0") {
            return crate::psb::parse_source(&data, None).map(|psb| Some(ScriptContent::Psb(psb)));
        }
        if data.starts_with(&[0xfa, 0xfa]) {
            return Ok(None);
        }
        Ok(std::str::from_utf8(data)
            .ok()
            .map(|text| ScriptContent::Text(text.trim_start_matches('\u{feff}').to_owned())))
    }
}
nvlens_core::inventory::submit! {ScriptRegistration(||Box::new(Kaleido))}
