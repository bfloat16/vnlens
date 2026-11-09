//! Escu:de's host scripts are pseudo-C source (CP932 or UTF-8), kept as text.
//! The host's misc/script.c and misc/script.inc additionally define @code:__
//! scenario programs and @mess:__ message tables. MDB/LSF/MOT are structured
//! resources read by misc/game.c and misc/anime.c, not pseudo-C programs.
mod database;
mod graphics;
mod motion;
mod procedure;
mod scenario;
mod sound;
mod source;
use crate::{ScriptFormat, ScriptRegistration, ir::*};
use nvlens_core::{ArchiveOptions, Error, Format, ResourceResolver, Result};
use nvlens_io::BinaryReader;
use std::borrow::Cow;

const SIGNATURES: &[u32] = &[
    0x646f_6340,
    0x7365_6d40,
    0x0062_646d,
    0x0046_534c,
    0x0054_4f4d,
    0x0074_6f6d,
];

#[derive(Debug, Default)]
struct Escude;
impl Format for Escude {
    fn tag(&self) -> &'static str {
        "script/escude"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["bin", "001", "lsf", "mot"]
    }
    fn description(&self) -> &'static str {
        "Escu:de scenario and structured resources"
    }
}
impl ScriptFormat for Escude {
    fn decode<'a>(&self, data: &'a [u8], _: &ArchiveOptions) -> Result<Cow<'a, [u8]>> {
        decode_envelope(data)
    }
    fn disassemble(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
    ) -> Result<Option<Script>> {
        if data.starts_with(b"@code:__") {
            let mut script = scenario::code(data)?;
            scenario::resolve(&mut script, resources)?;
            Ok(Some(script))
        } else if data.starts_with(b"@mess:__") {
            scenario::messages(data).map(Some)
        } else if data.starts_with(b"mdb\0") {
            database::parse(data).map(Some)
        } else if data.starts_with(b"LSF\0") {
            graphics::lsf(data).map(Some)
        } else if data.starts_with(b"MOT\0") || data.starts_with(b"mot\0") {
            graphics::mot(data).map(Some)
        } else {
            Ok(None)
        }
    }
}
nvlens_core::inventory::submit! { ScriptRegistration(||Box::new(Escude)) }

#[derive(Debug, Default)]
struct Text;
impl Format for Text {
    fn tag(&self) -> &'static str {
        "text/escude"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["c", "h", "inc", "txt", "cfg", "001"]
    }
    fn description(&self) -> &'static str {
        "Escu:de pseudo-C source and text"
    }
}
impl ScriptFormat for Text {
    fn decode<'a>(&self, data: &'a [u8], _: &ArchiveOptions) -> Result<Cow<'a, [u8]>> {
        decode_envelope(data)
    }
    fn disassemble(
        &self,
        data: &[u8],
        resources: Option<&dyn ResourceResolver>,
    ) -> Result<Option<Script>> {
        Escude.disassemble(data, resources)
    }
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        if data.starts_with(b"@mess:__") {
            return Ok(None);
        }
        if let Ok(text) = std::str::from_utf8(data) {
            return Ok(Some(text.into()));
        }
        let (text, _, errors) = encoding_rs::SHIFT_JIS.decode(data);
        if errors {
            return Err(bad(0, "Invalid Escu:de CP932 source text"));
        }
        Ok(Some(text.into_owned()))
    }
}
nvlens_core::inventory::submit! { ScriptRegistration(||Box::new(Text)) }

/// Removes the ACP resource envelope once, before script/content decoding.
/// Archives use the same entry point for embedded ACP resources.
pub fn decode_envelope(data: &[u8]) -> Result<Cow<'_, [u8]>> {
    if data.starts_with(b"acp\0") {
        let decoded = nvlens_crypto::compress::acp::unpack(data).map_err(|error| {
            if error.kind() == std::io::ErrorKind::InvalidInput {
                bad(0, &error.to_string())
            } else {
                error.into()
            }
        })?;
        Ok(Cow::Owned(decoded))
    } else {
        Ok(Cow::Borrowed(data))
    }
}
fn bad(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
fn span(offset: usize, size: usize) -> Span {
    Span {
        offset: offset as u64,
        size: size as u64,
    }
}
fn arg(name: ArgName, offset: usize, size: usize, value: Value) -> Arg {
    Arg {
        name,
        native_name: None,
        span: span(offset, size),
        value,
        attributes: Vec::new(),
    }
}
fn number(name: ArgName, offset: usize, value: u32) -> Arg {
    arg(name, offset, 4, Value::Unsigned(u64::from(value)))
}
fn text(bytes: &[u8]) -> Value {
    let (text, _, errors) = encoding_rs::SHIFT_JIS.decode(bytes);
    if errors {
        Value::Bytes(bytes.to_vec())
    } else {
        Value::Text(text.into_owned())
    }
}
fn cstring(data: &[u8], offset: usize) -> Result<&[u8]> {
    let mut r = BinaryReader::new_at(data, offset)?;
    while r.read_u8()? != 0 {}
    Ok(&data[offset..r.position() - 1])
}
fn script(data: &[u8], format: &str, version: u32) -> Script {
    Script {
        ir_version: VERSION,
        format: format.into(),
        format_version: version,
        sections: vec![Section {
            name: "resource".into(),
            span: span(0, data.len()),
            raw: data.to_vec(),
        }],
        instructions: Vec::new(),
    }
}
fn record(script: &mut Script, offset: usize, size: usize, variant: Qualifier, args: Vec<Arg>) {
    script.instructions.push(Instruction {
        id: script.instructions.len() as u64,
        span: span(offset, size),
        source_line: None,
        opcode: Opcode {
            operation: Operation::Data(DataOperation::Record),
            variant: Some(variant),
            namespace: script.format.clone(),
            code: 0,
            native_mnemonic: None,
        },
        args,
        attributes: Vec::new(),
    });
}

#[cfg(test)]
#[path = "../../tests/escude/mod.rs"]
mod tests;
