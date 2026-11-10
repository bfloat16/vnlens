//! SystemNNN scripts: SPT bytecode and CP932 text (XTX/MML, inverted FXF).
//! CScript's loader inverts stored SPT words; its interpreter consumes
//! length-prefixed LE records. Name-list and FXF loaders use CP932 bytes.
mod choice;
mod control_flow;
mod effect;
mod expression;
mod opcode;
mod record;
mod spt;
mod text;
use crate::{ScriptFormat, ScriptRegistration, ir::Script};
use std::borrow::Cow;
use vnlens_core::{ArchiveOptions, Format, ResourceResolver, Result};

const SIGNATURES: &[u32] = &[0];
#[derive(Debug, Default)]
struct Spt;
impl Format for Spt {
    fn tag(&self) -> &'static str {
        "spt/systemnnn"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["spt"]
    }
    fn description(&self) -> &'static str {
        "SystemNNN SPT bytecode"
    }
}
impl ScriptFormat for Spt {
    fn decode<'a>(&self, data: &'a [u8], _: &ArchiveOptions) -> Result<Cow<'a, [u8]>> {
        spt::decode(data)
    }
    fn disassemble(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
    ) -> Result<Option<Script>> {
        spt::parse(data, resources).map(Some)
    }
}
vnlens_core::inventory::submit! {ScriptRegistration(||Box::new(Spt))}

#[derive(Debug, Default)]
struct Fxf;
impl Format for Fxf {
    fn tag(&self) -> &'static str {
        "fxf/systemnnn"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["fxf"]
    }
    fn description(&self) -> &'static str {
        "SystemNNN inverted CP932 configuration"
    }
}
impl ScriptFormat for Fxf {
    fn decode<'a>(&self, data: &'a [u8], _: &ArchiveOptions) -> Result<Cow<'a, [u8]>> {
        let mut bytes = data.to_vec();
        vnlens_crypto::cipher::xor::apply_u32_key(&mut bytes, &[255; 4]);
        Ok(Cow::Owned(bytes))
    }
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        text::decode(data).map(Some)
    }
    fn disassemble(&self, _: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        Ok(None)
    }
}
vnlens_core::inventory::submit! {ScriptRegistration(||Box::new(Fxf))}

#[derive(Debug, Default)]
struct Text;
impl Format for Text {
    fn tag(&self) -> &'static str {
        "text/systemnnn"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["xtx", "mml"]
    }
    fn description(&self) -> &'static str {
        "SystemNNN CP932 text"
    }
}
impl ScriptFormat for Text {
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        text::decode(data).map(Some)
    }
    fn disassemble(&self, _: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        Ok(None)
    }
}
vnlens_core::inventory::submit! {ScriptRegistration(||Box::new(Text))}
