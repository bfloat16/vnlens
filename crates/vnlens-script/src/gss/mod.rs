//! GSS SCR 3.00 bytecode, verified against DistortedCode's dispatcher
//! sub_138F0 (u16 opcode, u8 length, unknown byte, i16 line) and operand readers
//! sub_7EEC/sub_8198/sub_837C. Instructions start at 0x10; a zero first byte
//! terminates execution. Unknown opcodes and operand tails remain lossless.
use crate::{
    ScriptFormat, ScriptRegistration,
    ir::{
        self, Arg, ArgName, Attribute, ControlFlowOperation as Flow, DataOperation, Instruction,
        Opcode, Operation, Script, Section, Span, TextOperation, Value,
    },
};
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{Error, Format, ResourceResolver, Result};
use vnlens_io::BinaryReader;

#[derive(Debug, Default)]
struct Scr;
impl Format for Scr {
    fn tag(&self) -> &'static str {
        "scr/gss"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x2052_4353]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["obj"]
    }
    fn description(&self) -> &'static str {
        "GSS SCR bytecode"
    }
}
impl ScriptFormat for Scr {
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        parse(data, &AtomicBool::new(false)).map(Some)
    }
    fn disassemble_cancellable(
        &self,
        data: &[u8],
        _: Option<&dyn ResourceResolver>,
        _: &vnlens_core::ArchiveOptions,
        cancel: &AtomicBool,
    ) -> Result<Option<Script>> {
        parse(data, cancel).map(Some)
    }
}
vnlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Scr)) }

fn parse(data: &[u8], cancel: &AtomicBool) -> Result<Script> {
    check(cancel)?;
    let mut reader = BinaryReader::new(data);
    let header = reader.read_bytes(16)?;
    if &header[..4] != b"SCR " {
        return Err(Error::InvalidFormat);
    }
    if &header[4..8] != b"3.00" {
        return Err(Error::Unsupported("GSS SCR version".into()));
    }
    let mut instructions = vec![Instruction {
        id: 0,
        span: Span {
            offset: 0,
            size: 16,
        },
        source_line: None,
        opcode: Opcode {
            operation: Operation::Data(DataOperation::Record),
            variant: None,
            namespace: "gss.header".into(),
            code: 0,
            native_mnemonic: None,
        },
        args: vec![
            arg(
                ArgName::Unknown(0),
                8,
                4,
                Value::Unsigned(u64::from(BinaryReader::u32_le(&header[8..]))),
            ),
            arg(
                ArgName::LabelBase,
                12,
                4,
                Value::Unsigned(u64::from(BinaryReader::u32_le(&header[12..]))),
            ),
        ],
        attributes: Vec::new(),
    }];
    while reader.remaining() != 0 {
        check(cancel)?;
        let at = reader.position();
        if data[at] == 0 {
            break;
        }
        let raw_header = reader.read_bytes(6)?;
        let code = BinaryReader::u16_le(raw_header);
        let size = usize::from(raw_header[2]);
        if size < 6 {
            return Err(bad(
                at as u64 + 2,
                "GSS instruction length is smaller than its header",
            ));
        }
        let raw = reader.read_bytes(size - 6)?;
        let mut args = Vec::new();
        let mut operands = BinaryReader::new(raw);
        while operands.remaining() != 0 {
            check(cancel)?;
            let start = operands.position();
            let tag = operands.read_u8()?;
            let mut attributes = vec![attribute("tag", u64::from(tag))];
            let value = match tag {
                1 => Value::Integer(i64::from(operands.read_u32_le()? as i32)),
                2 | 4 | 6 => Value::Unsigned(u64::from(operands.read_u16_le()?)),
                3 => {
                    let begin = operands.position();
                    while operands.read_u8()? != 0 {}
                    let bytes = &raw[begin..operands.position() - 1];
                    let (text, invalid) = encoding_rs::SHIFT_JIS.decode_without_bom_handling(bytes);
                    if invalid {
                        Value::Bytes(bytes.to_vec())
                    } else {
                        Value::Text(text.into_owned())
                    }
                }
                5 => {
                    let index = operands.read_u16_le()?;
                    let base = operands.read_u16_le()?;
                    Value::Group(vec![
                        arg(
                            ArgName::Index,
                            (at + 6 + start + 1) as u64,
                            2,
                            Value::Unsigned(u64::from(index)),
                        ),
                        arg(
                            ArgName::ArgumentBase,
                            (at + 6 + start + 3) as u64,
                            2,
                            Value::Unsigned(u64::from(base)),
                        ),
                    ])
                }
                _ => {
                    operands.read_bytes(operands.remaining())?;
                    attributes.push(attribute("opaque", 1));
                    Value::Bytes(raw[start..].to_vec())
                }
            };
            let mut operand = arg(
                ArgName::Value,
                (at + 6 + start) as u64,
                (operands.position() - start) as u64,
                value,
            );
            operand.attributes = attributes;
            args.push(operand);
        }
        let operation = match code {
            0x18 | 0x19 | 0x1b | 0x1d | 0x20 | 0x21 => Operation::ControlFlow(Flow::Jump),
            0x1c | 0x1e => Operation::ControlFlow(Flow::Call),
            0x1f => Operation::ControlFlow(Flow::Return),
            0x22 => Operation::ControlFlow(Flow::Branch),
            0x1a | 0x23 => Operation::Data(DataOperation::Record),
            0x5a | 0xfc => Operation::Text(TextOperation::Show),
            _ => Operation::Unknown,
        };
        let line = BinaryReader::i16_le(&raw_header[4..]);
        instructions.push(Instruction {
            id: instructions.len() as u64,
            span: Span {
                offset: at as u64,
                size: size as u64,
            },
            source_line: u32::try_from(line).ok(),
            opcode: Opcode {
                operation,
                variant: None,
                namespace: "gss".into(),
                code: u32::from(code),
                native_mnemonic: None,
            },
            args,
            attributes: vec![
                attribute("header_byte_3", u64::from(raw_header[3])),
                attribute(
                    "line_bits",
                    u64::from(BinaryReader::u16_le(&raw_header[4..])),
                ),
            ],
        });
    }
    Ok(Script {
        ir_version: ir::VERSION,
        format: "scr/gss".into(),
        format_version: 300,
        sections: vec![Section {
            name: "source".into(),
            span: Span {
                offset: 0,
                size: data.len() as u64,
            },
            raw: data.to_vec(),
        }],
        instructions,
    })
}
fn arg(name: ArgName, offset: u64, size: u64, value: Value) -> Arg {
    Arg {
        name,
        native_name: None,
        span: Span { offset, size },
        value,
        attributes: Vec::new(),
    }
}
fn attribute(name: &str, value: u64) -> Attribute {
    Attribute {
        name: name.into(),
        value,
    }
}
fn check(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
fn bad(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "../../tests/gss/mod.rs"]
mod tests;
