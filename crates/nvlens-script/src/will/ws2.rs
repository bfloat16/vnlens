//! AdvHD WS2: byte opcodes and PE-defined typed args. Strings are UTF-16LE;
//! type 8 stores their separate two-byte terminator. Type 7 repeats the next
//! type using a byte count. Opcode 15 embeds choice records and a command.
//! The final two u32 values belong to the plaintext footer, not the code.
//! Verified against the WS2 constructor and parameter/choice readers.

use super::opcode;
use crate::ir::{self, Arg, ArgName, Attribute, Instruction, Script, Section, Span, Token, Value};
use nvlens_core::{Error, Result};
use nvlens_io::BinaryReader;

pub(super) fn parse(data: &[u8], schema: &[u8]) -> Result<Script> {
    let end = data
        .len()
        .checked_sub(8)
        .ok_or_else(|| nvlens_io::BinaryIo::unexpected_eof("WS2 footer is missing"))?;
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
        let mut args = arguments(&mut r, table[usize::from(code)].unwrap_or_default())?;
        opcode::args(code, &mut args);
        if code == 15 {
            let count = data.get(start + 1).copied().ok_or_else(|| {
                nvlens_io::BinaryIo::unexpected_eof("WS2 choice count is missing")
            })?;
            for i in 0..count {
                let begin = r.position();
                let mut fields = vec![value(&mut r, 2, ArgName::Id)?];
                fields.push(value(&mut r, 6, ArgName::Text)?);
                fields.push(value(&mut r, 8, ArgName::Terminator(0))?);
                fields.push(value(&mut r, 0, ArgName::Flags)?);
                fields.push(value(&mut r, 1, ArgName::Condition)?);
                let op_at = r.position();
                let command = r.read_u8()?;
                let mut arguments =
                    arguments(&mut r, table[usize::from(command)].unwrap_or_default())?;
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
fn arguments(r: &mut BinaryReader<'_>, types: &[u8]) -> Result<Vec<Arg>> {
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
                values.push(value(r, kind, ArgName::ValueAt(n as u64))?);
                if matches!(kind, 6 | 9) {
                    values.push(value(r, 8, ArgName::Terminator(n as u64))?);
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
fn value(r: &mut BinaryReader<'_>, kind: u8, name: ArgName) -> Result<Arg> {
    let start = r.position();
    let v = match kind {
        0 => Value::Unsigned(u64::from(r.read_u8()?)),
        1 => Value::Integer(i64::from(r.read_u16_le()? as i16)),
        2 | 8 => Value::Unsigned(u64::from(r.read_u16_le()?)),
        3 => Value::Integer(i64::from(r.read_u32_le()? as i32)),
        4 => Value::Unsigned(u64::from(r.read_u32_le()?)),
        5 => Value::Float32Bits(r.read_u32_le()?),
        6 | 9 | 10 => {
            let mut units = Vec::new();
            loop {
                let unit = r.read_u16_le()?;
                if unit == 0 {
                    r.set_position(r.position() - 2)?;
                    break;
                }
                units.push(unit);
            }
            Value::Text(String::from_utf16(&units).map_err(|_| Error::Corrupt {
                offset: start as u64,
                reason: "Invalid WS2 UTF-16 string".into(),
            })?)
        }
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::Ws2;
    use super::*;
    use crate::ScriptFormat;
    use crate::ir::{ControlFlowOperation, Operation};
    use nvlens_io::BinaryWriter;
    fn schema(records: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for id in 0..=255 {
            if let Some((_, types)) = records.iter().find(|(i, _)| *i == id) {
                out.extend_from_slice(types);
                out.push(255);
            } else {
                out.push(254);
            }
        }
        out
    }
    fn string(data: &mut Vec<u8>, text: &str) {
        for unit in text.encode_utf16().chain([0]) {
            let mut b = [0; 2];
            BinaryWriter::u16_le(unit, &mut b);
            data.extend(b);
        }
    }
    #[test]
    fn utf16_repeats_and_choice_command_use_engine_schema() {
        let table = schema(&[(1, &[6, 8, 7, 9]), (15, &[0]), (2, &[4])]);
        let mut data = vec![1];
        string(&mut data, "あ🦀");
        data.push(2);
        string(&mut data, "one");
        string(&mut data, "two");
        data.extend([15, 1, 7, 0]);
        string(&mut data, "choice");
        data.extend([1, 255, 255, 2, 42, 0, 0, 0, 255]);
        data.extend([1, 2, 3, 4, 5, 6, 7, 8]);
        let script = parse(&data, &table).unwrap();
        assert_eq!(script.instructions.len(), 3);
        assert_eq!(
            script.instructions[2].opcode.operation,
            Operation::ControlFlow(ControlFlowOperation::Halt)
        );
        assert!(matches!(&script.instructions[0].args[0].value,Value::Text(s) if s=="あ🦀"));
        assert!(
            matches!(&script.instructions[1].args[1].value, Value::Group(f)
                if matches!(f.last().map(|f| &f.value), Some(Value::Expression(tokens))
                    if tokens[0].opcode.operation == Operation::ControlFlow(ControlFlowOperation::Jump)
                    && matches!(tokens[0].args[0].value, Value::CodeAddress(42))))
        );
        assert_eq!(script.sections[1].raw, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(parse(&data[..10], &table).is_err());
        assert!(Ws2.disassemble(&data, None).is_err());
    }
    #[test]
    fn float_bits_unknown_opcodes_and_truncated_operands_are_retained() {
        let table = schema(&[(1, &[5])]);
        let mut bytes = vec![1, 1, 0, 0xc0, 0x7f, 3];
        bytes.extend([0; 8]);
        let ir = parse(&bytes, &table).unwrap();
        assert!(matches!(
            ir.instructions[0].args[0].value,
            Value::Float32Bits(0x7fc00001)
        ));
        assert_eq!(ir.instructions[1].opcode.operation, Operation::Unknown);
        let mut short = vec![1, 0];
        short.extend([0; 8]);
        assert!(parse(&short, &table).is_err());
    }
}
