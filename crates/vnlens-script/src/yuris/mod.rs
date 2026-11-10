//! YU-RIS YBN bytecode and script table disassembly.

mod expression;
mod opcode;
mod tables;
mod ybn;

pub use tables::script_paths;
pub use ybn::decrypt_ystb;

use crate::{ScriptFormat, ScriptRegistration, ir::*};
use vnlens_core::{Error, Format, ResourceResolver, Result};
use vnlens_io::BinaryReader;

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
struct YbnScript;
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
        if data.len() < 4 || !SIGNATURES.contains(&vnlens_io::BinaryReader::u32_le(data)) {
            return Ok(None);
        }
        Ok(Some(ybn::disassemble(data, resources)?))
    }
}
vnlens_core::inventory::submit! {ScriptRegistration(||Box::new(YbnScript))}

pub(super) fn corrupt(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
pub(super) fn attribute(name: &str, value: impl Into<u64>) -> Attribute {
    Attribute {
        name: name.into(),
        value: value.into(),
    }
}
pub(super) fn operand(name: ArgName, span: Span, value: Value) -> Arg {
    Arg {
        name,
        native_name: None,
        span,
        value,
        attributes: Vec::new(),
    }
}
pub(super) fn section(name: &str, data: &[u8], range: std::ops::Range<usize>) -> Section {
    Section {
        name: name.into(),
        span: Span {
            offset: range.start as u64,
            size: range.len() as u64,
        },
        raw: data[range].to_vec(),
    }
}

pub(super) fn c_string(reader: &mut BinaryReader<'_>) -> Result<String> {
    let offset = reader.position();
    let mut bytes = Vec::new();
    loop {
        let byte = reader.read_u8()?;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
    }
    expression::text(&bytes, offset as u64)
}
