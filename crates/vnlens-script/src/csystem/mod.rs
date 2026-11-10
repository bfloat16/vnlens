//! C,system scenario records (sub_497A90): LE u32 byte length, M/subtype
//! command with N/A integer operands, or T/id/length/UTF-16LE text. Text code
//! units are XORed by their count (sub_47A9D0); record terminators are u32 9999.
use crate::{ScriptFormat, ScriptRegistration, ir::*};
use vnlens_core::{Error, Format, ResourceResolver, Result};
use vnlens_io::BinaryReader;
mod resource;
#[derive(Debug, Default)]
struct Csystem;
impl Format for Csystem {
    fn tag(&self) -> &'static str {
        "script/csystem"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["a0"]
    }
    fn description(&self) -> &'static str {
        "C,system scenario bytecode"
    }
}
impl ScriptFormat for Csystem {
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        let mut r = BinaryReader::new(data);
        let mut instructions = Vec::new();
        while r.remaining() != 0 {
            let start = r.position();
            let length = r.read_u32_le()? as usize;
            let bytes = r.read_bytes(length)?;
            if bytes.is_empty() {
                continue;
            }
            let mut body = BinaryReader::new(bytes);
            let marker = body.read_u8()?;
            let mut args = Vec::new();
            let (namespace, code, operation) = match marker {
                b'M' => {
                    let subtype = body.read_u8()?;
                    let tag = body.read_u8()?;
                    let code = body.read_u32_le()?;
                    args.push(argument(
                        start + 6,
                        5,
                        Value::Unsigned(u64::from(code)),
                        vec![Attribute {
                            name: "tag".into(),
                            value: u64::from(tag),
                        }],
                    ));
                    (
                        format!("csystem.command.{subtype:02x}"),
                        code,
                        Operation::Native,
                    )
                }
                b'T' => {
                    args.push(text(&mut body, start + 4, 0)?);
                    (
                        "csystem.text".into(),
                        u32::from(marker),
                        Operation::Text(TextOperation::Show),
                    )
                }
                _ => (
                    "csystem.record".into(),
                    u32::from(marker),
                    Operation::Unknown,
                ),
            };
            while body.remaining() > 4 {
                let at = body.position();
                let tag = body.read_u8()?;
                let value = match tag {
                    b'N' | b'A' => Value::Integer(i64::from(body.read_u32_le()? as i32)),
                    b'T' => {
                        args.push(text(&mut body, start + 4, at)?);
                        continue;
                    }
                    _ => {
                        body = BinaryReader::new_at(bytes, at)?;
                        Value::Bytes(body.read_bytes(body.remaining())?.to_vec())
                    }
                };
                args.push(argument(
                    start + 4 + at,
                    body.position() - at,
                    value,
                    vec![Attribute {
                        name: "tag".into(),
                        value: u64::from(tag),
                    }],
                ));
            }
            if body.remaining() != 0 {
                let at = body.position();
                if body.read_u32_le()? != 9999 {
                    return Err(bad(start + 4 + at, "Invalid C,system record terminator"));
                }
            }
            instructions.push(Instruction {
                id: instructions.len() as u64,
                span: Span {
                    offset: start as u64,
                    size: (length + 4) as u64,
                },
                source_line: None,
                opcode: Opcode {
                    operation,
                    variant: None,
                    namespace,
                    code,
                    native_mnemonic: None,
                },
                args,
                attributes: Vec::new(),
            });
        }
        Ok(Some(Script {
            ir_version: VERSION,
            format: "C,system".into(),
            format_version: 1,
            sections: vec![Section {
                name: "source".into(),
                span: Span {
                    offset: 0,
                    size: data.len() as u64,
                },
                raw: data.to_vec(),
            }],
            instructions,
        }))
    }
}
fn text(r: &mut BinaryReader<'_>, base: usize, start: usize) -> Result<Arg> {
    let id = r.read_u32_le()?;
    let count = r.read_u32_le()?;
    let bytes = r.read_bytes(
        usize::try_from(u64::from(count) * 2)
            .map_err(|_| bad(base + start, "C,system text exceeds address space"))?,
    )?;
    let mut units = BinaryReader::new(bytes);
    let mut text = Vec::new();
    while units.remaining() != 0 {
        text.push(units.read_u16_le()? ^ count as u16);
    }
    let value =
        String::from_utf16(&text).map_err(|_| bad(base + start, "Invalid C,system UTF-16 text"))?;
    Ok(argument(
        base + start,
        r.position() - start,
        Value::Text(value),
        vec![Attribute {
            name: "text_id".into(),
            value: u64::from(id),
        }],
    ))
}
fn argument(offset: usize, size: usize, value: Value, attributes: Vec<Attribute>) -> Arg {
    Arg {
        name: ArgName::Value,
        native_name: None,
        span: Span {
            offset: offset as u64,
            size: size as u64,
        },
        value,
        attributes,
    }
}
fn bad(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
vnlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Csystem)) }
#[cfg(test)]
#[path = "../../tests/csystem/mod.rs"]
mod tests;
