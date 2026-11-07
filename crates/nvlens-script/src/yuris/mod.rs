//! YU-RIS YBN bytecode and script table disassembly.

mod expression;
mod tables;
mod ybn;

pub use tables::script_paths;
pub use ybn::decrypt_ystb;

use crate::{ScriptFormat, ScriptRegistration, ir::Script};
use nvlens_core::{Format, ResourceResolver, Result};

const SIGNATURES: &[u32] = &[
    0x4254_5359,
    0x4d43_5359,
    0x4643_5359,
    0x5245_5359,
    0x424c_5359,
    0x4454_5359,
    0x4c54_5359,
    0x5256_5359,
];

#[derive(Debug, Default)]
pub struct YbnScript;
impl Format for YbnScript {
    fn tag(&self) -> &'static str {
        "ybn/yuris"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["ybn"]
    }
    fn description(&self) -> &'static str {
        "YU-RIS bytecode and script tables"
    }
}
impl ScriptFormat for YbnScript {
    fn disassemble(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
    ) -> Result<Option<Script>> {
        if data.len() < 4 || !SIGNATURES.contains(&nvlens_io::BinaryReader::u32_le(data)) {
            return Ok(None);
        }
        Ok(Some(ybn::disassemble(data, resources)?))
    }
}
nvlens_core::inventory::submit! {ScriptRegistration(||Box::new(YbnScript))}
