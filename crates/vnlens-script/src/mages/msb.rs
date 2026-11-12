//! MES v1: LE header, (message ID, relative offset) records; FFFFFFFF denotes
//! an absent localized message. Glyphs are BE u16/u32 with the high bit set,
//! selected by the identified engine reader; controls are bytes, terminator FF.
//! Name/side runs are rendering controls, not encoded Unicode text.
use super::{arg, corrupt, expression, op, section, span};
use crate::ir::*;
use vnlens_core::{Error, Result};
use vnlens_io::BinaryReader;

pub(super) fn disassemble(data: &[u8], glyph_width: usize) -> Result<Script> {
    let mut reader = BinaryReader::new(data);
    if reader.read_bytes(4)? != b"MES\0" {
        return Err(Error::InvalidFormat);
    }
    let version = reader.read_u32_le()?;
    if version != 1 {
        return Err(Error::Unsupported(format!("MES version {version}")));
    }
    let count = reader.read_u32_le()? as usize;
    let start = reader.read_u32_le()? as usize;
    if count.checked_mul(8).and_then(|n| n.checked_add(16)) != Some(start) {
        return Err(corrupt(12, "MES index size does not match data offset"));
    }
    reader.read_bytes(start - 16)?;
    let mut table = BinaryReader::new(&data[16..start]);
    let mut entries = Vec::new();
    for _ in 0..count {
        let id = table.read_u32_le()?;
        let relative = table.read_u32_le()?;
        if relative == u32::MAX {
            entries.push((id, None));
            continue;
        }
        let offset = (relative as usize)
            .checked_add(start)
            .filter(|&p| p <= data.len())
            .ok_or_else(|| corrupt(table.position() + 12, "MES message exceeds file"))?;
        entries.push((id, Some(offset)));
    }
    let mut script = Script {
        ir_version: VERSION,
        format: "msb/mages".into(),
        format_version: version,
        sections: vec![
            section("header", data, 0, 16),
            section("index", data, 16, start),
            section("messages", data, start, data.len()),
        ],
        instructions: Vec::new(),
    };
    let offsets: std::collections::BTreeSet<usize> = entries.iter().filter_map(|e| e.1).collect();
    for (i, &(id, offset)) in entries.iter().enumerate() {
        let (start, end, value) = if let Some(offset) = offset {
            let end = offsets
                .range((
                    std::ops::Bound::Excluded(offset),
                    std::ops::Bound::Unbounded,
                ))
                .next()
                .copied()
                .unwrap_or(data.len());
            (
                offset,
                end,
                Value::Expression(message(&data[offset..end], offset, glyph_width)?),
            )
        } else {
            (20 + i * 8, 24 + i * 8, Value::Nil)
        };
        script.instructions.push(Instruction {
            id: i as u64,
            span: span(start, end),
            source_line: None,
            opcode: op("mages/mes", 0, Operation::Data(DataOperation::Record)),
            args: vec![
                arg(
                    ArgName::MessageIndex,
                    16 + i * 8,
                    20 + i * 8,
                    Value::Unsigned(u64::from(id)),
                ),
                arg(ArgName::Message, start, end, value),
            ],
            attributes: Vec::new(),
        });
    }
    Ok(script)
}

pub(super) fn message(data: &[u8], base: usize, glyph_width: usize) -> Result<Vec<Token>> {
    let mut r = BinaryReader::new(data);
    let mut tokens = Vec::new();
    loop {
        let start = r.position();
        let code = r.read_u8()?;
        let mut args = Vec::new();
        let operation = if code == 0xff {
            Operation::ControlFlow(ControlFlowOperation::Halt)
        } else if code & 0x80 != 0 {
            r.set_position(start)?;
            let glyph = if glyph_width == 2 {
                u32::from(BinaryReader::u16_be(r.read_bytes(2)?) & 0x7fff)
            } else {
                BinaryReader::u32_be(r.read_bytes(4)?) & 0x7fff_ffff
            };
            args.push(arg(
                ArgName::GlyphId,
                base + start,
                base + r.position(),
                Value::Unsigned(u64::from(glyph)),
            ));
            Operation::Text(TextOperation::Show)
        } else {
            match code {
                4 | 0x15 => {
                    let at = r.position();
                    let expr = expression::read(&mut r, data, base)?;
                    args.push(arg(
                        if code == 4 {
                            ArgName::Color
                        } else {
                            ArgName::Value
                        },
                        base + at,
                        base + r.position(),
                        Value::Expression(expr),
                    ));
                }
                7 | 0x1b => {
                    let at = r.position();
                    let v = r.read_u8()?;
                    args.push(arg(
                        if code == 0x1b {
                            ArgName::StyleId
                        } else {
                            ArgName::Unknown(0)
                        },
                        base + at,
                        base + r.position(),
                        Value::Unsigned(u64::from(v)),
                    ));
                }
                0x0c | 0x11..=0x14 | 0x16 | 0x19 | 0x1a => {
                    let at = r.position();
                    let v = BinaryReader::u16_be(r.read_bytes(2)?);
                    args.push(arg(
                        match code {
                            0x0c => ArgName::ScaleY,
                            0x11 => ArgName::OffsetY,
                            0x12 => ArgName::OffsetX,
                            0x13 | 0x14 => ArgName::VariableId,
                            _ => ArgName::Unknown(0),
                        },
                        base + at,
                        base + r.position(),
                        Value::Unsigned(u64::from(v)),
                    ));
                }
                _ => {}
            }
            match code {
                0 => Operation::Text(TextOperation::LineBreak),
                1 | 0x0a => Operation::Text(TextOperation::BeginSpan),
                2 | 0x0b => Operation::Text(TextOperation::EndSpan),
                0x13 | 0x14 | 0x51..=0x57 => Operation::Text(TextOperation::Show),
                3..=5
                | 8
                | 9
                | 0x0c
                | 0x0e..=0x12
                | 0x15
                | 0x18..=0x1b
                | 0x1e
                | 0x20..=0x29
                | 0x31 => Operation::Text(TextOperation::Configure),
                _ => Operation::Unknown,
            }
        };
        let end = r.position();
        // sub_1400C8D60's controls operate on glyph runs, not Unicode text.
        // Generated mode/charset values have no additional source bytes.
        let derived = match code {
            3 => Some((ArgName::Mode, 1)),
            5 => Some((ArgName::Mode, 0)),
            8 => Some((ArgName::Mode, 2)),
            0x18 => Some((ArgName::Mode, 3)),
            0x19 => Some((ArgName::Mode, 4)),
            0x1a => Some((ArgName::Mode, 5)),
            0x0f => Some((ArgName::Alignment, 1)),
            0x10 => Some((ArgName::Alignment, 0)),
            0x31 => Some((ArgName::Alignment, 2)),
            0x13 | 0x14 => Some((ArgName::CharacterSet, u64::from(code - 0x13))),
            0x20..=0x29 => Some((ArgName::Index, u64::from(code - 0x20))),
            0x51..=0x57 => Some((ArgName::Index, u64::from(code - 0x50))),
            _ => None,
        };
        if let Some((name, value)) = derived {
            args.push(arg(
                name,
                base + start,
                base + start,
                Value::Unsigned(value),
            ));
        }
        let mut opcode = op("mages/mes-token", u32::from(code), operation);
        opcode.variant = match code {
            1 | 2 | 9 => Some(Qualifier::Speaker),
            0x0a | 0x0b | 0x1e => Some(Qualifier::Ruby),
            0x13 | 0x14 => Some(Qualifier::Number),
            0x80..=0xfe => Some(Qualifier::Glyph),
            _ => None,
        };
        if code == 0xff {
            opcode.operation = Operation::Text(TextOperation::End);
        }
        tokens.push(Token {
            opcode,
            span: span(base + start, base + end),
            args,
            raw: data[start..end].to_vec(),
        });
        if code == 0xff {
            return Ok(tokens);
        }
    }
}
