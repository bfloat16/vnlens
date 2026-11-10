//! AdvHD WS2: byte opcodes and PE-defined typed args. Strings are CP932 in
//! sub_4E4E40/sub_4CC610 and UTF-16LE in the x64 reader; type 8 stores their
//! separate one- or two-byte terminator. Type 7 repeats the next
//! type using a byte count. Opcode 15 embeds choice records and a command.
//! The final two u32 values belong to the plaintext footer, not the code.
//! Verified against the WS2 constructor and parameter/choice readers.

use super::opcode;
use crate::ir::{self, Arg, ArgName, Attribute, Instruction, Script, Section, Span, Token, Value};
use vnlens_core::{Error, Result};
use vnlens_io::BinaryReader;

#[derive(Clone, Copy, Debug)]
pub(super) enum TextEncoding {
    Cp932,
    Utf16,
}

pub(super) fn parse(data: &[u8], schema: &[u8], encoding: TextEncoding) -> Result<Script> {
    let end = data
        .len()
        .checked_sub(8)
        .ok_or_else(|| vnlens_io::BinaryIo::unexpected_eof("WS2 footer is missing"))?;
    let mut table = Vec::new();
    let mut start = 0;
    for (i, &b) in schema.iter().enumerate() {
        if b >= 128 {
            table.push((b == 255).then_some(&schema[start..i]));
            start = i + 1;
        }
    }
    if table.len() != 256 || start != schema.len() {
        return Err(Error::UnknownScheme(Some(
            "Invalid AdvHD parameter table".into(),
        )));
    }
    let mut r = BinaryReader::new(&data[..end]);
    let mut instructions = Vec::new();
    while r.remaining() != 0 {
        let start = r.position();
        let code = r.read_u8()?;
        let mut args = arguments(
            &mut r,
            table[usize::from(code)].unwrap_or_default(),
            encoding,
        )?;
        opcode::args(code, &mut args);
        if code == 15 {
            let count = data.get(start + 1).copied().ok_or_else(|| {
                vnlens_io::BinaryIo::unexpected_eof("WS2 choice count is missing")
            })?;
            for i in 0..count {
                let begin = r.position();
                let mut fields = vec![value(&mut r, 2, ArgName::Id, encoding)?];
                fields.push(value(&mut r, 6, ArgName::Text, encoding)?);
                fields.push(value(&mut r, 8, ArgName::Terminator(0), encoding)?);
                fields.push(value(&mut r, 0, ArgName::Flags, encoding)?);
                fields.push(value(&mut r, 1, ArgName::Condition, encoding)?);
                let op_at = r.position();
                let command = r.read_u8()?;
                let mut arguments = arguments(
                    &mut r,
                    table[usize::from(command)].unwrap_or_default(),
                    encoding,
                )?;
                opcode::args(command, &mut arguments);
                let span = Span {
                    offset: op_at as u64,
                    size: (r.position() - op_at) as u64,
                };
                fields.push(operand(
                    ArgName::Command,
                    op_at,
                    r.position() - op_at,
                    Value::Expression(vec![Token {
                        opcode: opcode::opcode(command),
                        span,
                        args: arguments,
                        raw: data[op_at..r.position()].to_vec(),
                    }]),
                    0,
                ));
                args.push(operand(
                    ArgName::Choice(i as u64),
                    begin,
                    r.position() - begin,
                    Value::Group(fields),
                    15,
                ));
            }
        }
        instructions.push(Instruction {
            id: instructions.len() as u64,
            span: Span {
                offset: start as u64,
                size: (r.position() - start) as u64,
            },
            source_line: None,
            opcode: opcode::opcode(code),
            args,
            attributes: Vec::new(),
        });
    }
    Ok(Script {
        ir_version: ir::VERSION,
        format: "WS2/AdvHD".into(),
        format_version: 2,
        sections: vec![
            Section {
                name: "code".into(),
                span: Span {
                    offset: 0,
                    size: end as u64,
                },
                raw: data[..end].to_vec(),
            },
            Section {
                name: "footer".into(),
                span: Span {
                    offset: end as u64,
                    size: 8,
                },
                raw: data[end..].to_vec(),
            },
        ],
        instructions,
    })
}
fn arguments(r: &mut BinaryReader<'_>, types: &[u8], encoding: TextEncoding) -> Result<Vec<Arg>> {
    let mut fields = Vec::new();
    let mut i = 0;
    while let Some(&kind) = types.get(i) {
        if kind == 7 {
            let count_at = r.position();
            let count = r.read_u8()?;
            let mut values = vec![operand(
                ArgName::Count,
                count_at,
                1,
                Value::Unsigned(u64::from(count)),
                7,
            )];
            let kind = *types
                .get(i + 1)
                .ok_or_else(|| Error::UnknownScheme(Some("WS2 repeat type is missing".into())))?;
            for n in 0..count {
                values.push(value(r, kind, ArgName::ValueAt(n as u64), encoding)?);
                if matches!(kind, 6 | 9) {
                    values.push(value(r, 8, ArgName::Terminator(n as u64), encoding)?);
                }
            }
            let mut repeated = operand(
                ArgName::Unknown(i as u64),
                count_at,
                r.position() - count_at,
                Value::Group(values),
                7,
            );
            repeated.attributes.push(Attribute {
                name: "operand_id".into(),
                value: i as u64,
            });
            fields.push(repeated);
            break;
        }
        let mut field = value(
            r,
            kind,
            if kind == 8 {
                ArgName::Terminator(i as u64)
            } else {
                ArgName::Unknown(i as u64)
            },
            encoding,
        )?;
        field.attributes.push(Attribute {
            name: "operand_id".into(),
            value: i as u64,
        });
        fields.push(field);
        i += 1;
    }
    Ok(fields)
}
fn value(r: &mut BinaryReader<'_>, kind: u8, name: ArgName, encoding: TextEncoding) -> Result<Arg> {
    let start = r.position();
    let v = match kind {
        0 => Value::Unsigned(u64::from(r.read_u8()?)),
        1 => Value::Integer(i64::from(r.read_u16_le()? as i16)),
        2 => Value::Unsigned(u64::from(r.read_u16_le()?)),
        8 => Value::Unsigned(match encoding {
            TextEncoding::Cp932 => u64::from(r.read_u8()?),
            TextEncoding::Utf16 => u64::from(r.read_u16_le()?),
        }),
        3 => Value::Integer(i64::from(r.read_u32_le()? as i32)),
        4 => Value::Unsigned(u64::from(r.read_u32_le()?)),
        5 => Value::Float32Bits(r.read_u32_le()?),
        6 | 9 | 10 => Value::Text(match encoding {
            TextEncoding::Cp932 => {
                let mut bytes = Vec::new();
                loop {
                    let byte = r.read_u8()?;
                    if byte == 0 {
                        r.set_position(r.position() - 1)?;
                        break;
                    }
                    bytes.push(byte);
                }
                encoding_rs::SHIFT_JIS
                    .decode_without_bom_handling_and_without_replacement(&bytes)
                    .ok_or_else(|| Error::Corrupt {
                        offset: start as u64,
                        reason: "Invalid WS2 CP932 string".into(),
                    })?
                    .into_owned()
            }
            TextEncoding::Utf16 => {
                let mut units = Vec::new();
                loop {
                    let unit = r.read_u16_le()?;
                    if unit == 0 {
                        r.set_position(r.position() - 2)?;
                        break;
                    }
                    units.push(unit);
                }
                String::from_utf16(&units).map_err(|_| Error::Corrupt {
                    offset: start as u64,
                    reason: "Invalid WS2 UTF-16 string".into(),
                })?
            }
        }),
        _ => {
            return Err(Error::UnknownScheme(Some(
                "Unknown WS2 parameter type".into(),
            )));
        }
    };
    Ok(operand(name, start, r.position() - start, v, kind))
}
fn operand(name: ArgName, start: usize, size: usize, value: Value, kind: u8) -> Arg {
    Arg {
        name,
        native_name: None,
        span: Span {
            offset: start as u64,
            size: size as u64,
        },
        value,
        attributes: vec![Attribute {
            name: "parameter_type".into(),
            value: u64::from(kind),
        }],
    }
}

#[cfg(test)]
#[path = "../../tests/will/ws2.rs"]
mod tests;
