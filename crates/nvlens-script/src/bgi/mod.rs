//! BGI bytecode has separate compact native programs (_bp) and 32-bit
//! BurikoCompiledScriptVer1.00 programs. Both retain complete decoded bytes
//! in IR sections, with distinct opcode namespaces and operand spans.
mod compact;
mod compact_layout;
mod compiled;
mod opcode;
use crate::{ScriptFormat, ScriptRegistration, ir::*};
use nvlens_core::{Error, Format, ResourceResolver, Result};
use nvlens_io::BinaryReader;
#[derive(Debug, Default)]
struct BgiScript;
impl Format for BgiScript {
    fn tag(&self) -> &'static str {
        "script/bgi"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x6972_7542, 0x10]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["_bp", "bss"]
    }
    fn description(&self) -> &'static str {
        "BGI compact and compiled bytecode"
    }
}
impl ScriptFormat for BgiScript {
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        if data.starts_with(b"BurikoCompiledScriptVer1.00\0") {
            return compiled::parse(data).map(Some);
        }
        if data.len() >= 16 && BinaryReader::u32_le(data) == 16 && data[8..16] == [0; 8] {
            return compact::parse(data).map(Some);
        }
        Ok(None)
    }
}
nvlens_core::inventory::submit! { ScriptRegistration(|| Box::new(BgiScript)) }
fn corrupt(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
fn section(name: &str, offset: usize, bytes: &[u8]) -> Section {
    Section {
        name: name.into(),
        span: Span {
            offset: offset as u64,
            size: bytes.len() as u64,
        },
        raw: bytes.to_vec(),
    }
}
fn operand(name: ArgName, start: usize, end: usize, value: Value) -> Arg {
    Arg {
        name,
        native_name: None,
        span: Span {
            offset: start as u64,
            size: (end - start) as u64,
        },
        value,
        attributes: Vec::new(),
    }
}
fn text_at(data: &[u8], at: usize) -> Result<Value> {
    let bytes = data
        .get(at..)
        .ok_or_else(|| nvlens_io::BinaryIo::unexpected_eof("BGI string offset outside file"))?;
    let end = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| nvlens_io::BinaryIo::unexpected_eof("Unterminated BGI string"))?;
    // sub_1400FA2F0/1400FA400 select UTF-8 when the byte sequence is valid,
    // otherwise CP932. ASCII has the same representation in both encodings.
    if let Ok(text) = std::str::from_utf8(&bytes[..end]) {
        return Ok(Value::Text(text.to_owned()));
    }
    let (text, _, errors) = encoding_rs::SHIFT_JIS.decode(&bytes[..end]);
    // Font-specific byte sequences are legal resource data. Preserve them
    // verbatim when the standard CP932 mapping cannot represent the string.
    Ok(if errors {
        Value::Bytes(bytes[..end].to_vec())
    } else {
        Value::Text(text.into_owned())
    })
}
