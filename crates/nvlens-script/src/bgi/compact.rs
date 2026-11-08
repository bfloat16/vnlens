//! Compact VM disassembly. Header fields (code offset/length) follow
//! sub_140088C20. All args use the native readers' signedness; direct
//! branches and code-address literals use the instruction start as their base.
//! The instruction stream precedes the referenced data pool; references bound
//! the pool while unvisited bytes remain in the lossless program section.
use super::compact_layout::{Encoding, layout};
use super::opcode;
use super::*;
use crate::ir::ArgName;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn parse(data: &[u8]) -> Result<Script> {
    let mut header = BinaryReader::new(data);
    let base = header.read_u32_le()? as usize;
    let length = header.read_u32_le()? as usize;
    header.read_bytes(8)?;
    let mut body = BinaryReader::new_at(data, base)?;
    let bytes = body.read_bytes(length)?;
    let mut instructions = BTreeMap::new();
    let mut data_start = length;
    let mut pending = BTreeSet::from([0usize]);
    while let Some(mut pc) = pending.pop_first() {
        while pc < data_start && !instructions.contains_key(&pc) {
            if instructions
                .range(..pc)
                .next_back()
                .is_some_and(|(_, i): (&usize, &Instruction)| {
                    i.span.offset + i.span.size > (base + pc) as u64
                })
            {
                return Err(corrupt(base + pc, "BGI branch enters an operand"));
            }
            let mut r = BinaryReader::new_at(bytes, pc)?;
            let code = r.read_u8()?;
            let mut opcode = u32::from(code);
            let mut args = Vec::new();
            let mut read = |r: &mut BinaryReader<'_>, encoding: Encoding| -> Result<i64> {
                let start = r.position();
                let (value, tag) = match encoding {
                    Encoding::U8 => (i64::from(r.read_u8()?), None),
                    Encoding::I8 => (i64::from(r.read_u8()? as i8), None),
                    Encoding::I16 => (i64::from(BinaryReader::i16_le(r.read_bytes(2)?)), None),
                    Encoding::U16 => (i64::from(r.read_u16_le()?), None),
                    Encoding::I32 => (i64::from(BinaryReader::i32_le(r.read_bytes(4)?)), None),
                    Encoding::U32 => (i64::from(r.read_u32_le()?), None),
                    Encoding::I64 => (r.read_i64_le()?, None),
                    Encoding::Signed => (r.read_tagged_sleb64(0)?.1, None),
                    Encoding::Tagged => {
                        let (tag, value) = r.read_tagged_sleb64(2)?;
                        (value, Some(tag))
                    }
                };
                let mut op = operand(
                    ArgName::Unknown(args.len() as u64),
                    base + start,
                    base + r.position(),
                    Value::Integer(value),
                );
                if let Some(tag) = tag {
                    op.attributes.push(Attribute {
                        name: "width_tag".into(),
                        value: tag,
                    });
                }
                args.push(op);
                Ok(value)
            };
            match code {
                0x03 => {
                    let mode = read(&mut r, Encoding::U8)? as u8;
                    if mode < 128 {
                        for _ in 0..=mode {
                            read(&mut r, Encoding::Signed)?;
                        }
                    } else if mode & 0x7c == 0 {
                        read(
                            &mut r,
                            match mode & 3 {
                                0 => Encoding::I8,
                                1 => Encoding::I16,
                                2 => Encoding::I32,
                                _ => Encoding::I64,
                            },
                        )?;
                    }
                }
                0x0b => {
                    let count = read(&mut r, Encoding::U8)? as usize;
                    let start = r.position();
                    let bytes = r.read_bytes(count)?;
                    args.push(operand(
                        ArgName::Data,
                        base + start,
                        base + r.position(),
                        Value::Bytes(bytes.to_vec()),
                    ));
                }
                0x15 => {
                    let flags = read(&mut r, Encoding::U8)?;
                    if flags & 8 != 0 {
                        read(&mut r, Encoding::I16)?;
                    }
                }
                0xe2 | 0xe3 => {
                    let count = read(&mut r, Encoding::U8)?;
                    for _ in 0..=count {
                        read(&mut r, Encoding::U16)?;
                    }
                }
                0x7f | 0x80 | 0x81 | 0x90 | 0x91 | 0x92 | 0xa0 | 0xb0 | 0xc0 | 0xd0 | 0xe0
                | 0xff => {
                    r.read_u8()?;
                    opcode = u32::from(BinaryReader::u16_be(&bytes[pc..r.position()]));
                }
                _ => {
                    for &encoding in layout(code).ok_or_else(|| {
                        corrupt(base + pc, &format!("Invalid compact BGI opcode {code:#x}"))
                    })? {
                        read(&mut r, encoding)?;
                    }
                }
            }
            for (index, operand) in args.iter_mut().enumerate() {
                if let Some(name) = opcode::compact_arg(code, index) {
                    operand.name = name;
                } else if code == 0x03 && index > 0 {
                    operand.name = ArgName::ValueAt((index - 1) as u64);
                }
            }
            let target_index = match code {
                0x05 | 0x06 | 0x13 | 0xee => Some(0),
                0x15 if args.len() == 2 => Some(1),
                0x37 | 0x3b | 0xdc | 0xdd => Some(1),
                0xde | 0xdf => Some(0),
                _ => None,
            };
            if let Some(index) = target_index {
                let Value::Integer(relative) = args[index].value else {
                    return Err(corrupt(base + pc, "Invalid branch operand"));
                };
                let target = (pc as i64)
                    .checked_add(relative)
                    .and_then(|v| usize::try_from(v).ok())
                    .filter(|&v| v < length)
                    .ok_or_else(|| corrupt(base + pc, "Compact BGI reference outside program"))?;
                args[index].name = if code == 0x05 {
                    ArgName::DataOffset
                } else {
                    ArgName::Target
                };
                args[index].value = if code == 0x05 {
                    Value::DataAddress((base + target) as u64)
                } else {
                    Value::CodeAddress((base + target) as u64)
                };
                if code == 0x05 {
                    data_start = data_start.min(target);
                    if let Ok(text) = text_at(bytes, target) {
                        args.push(operand(
                            ArgName::Text,
                            base + target,
                            base + target + text_bytes(bytes, target),
                            text,
                        ));
                    }
                } else {
                    pending.insert(target);
                }
            }
            let end = r.position();
            if instructions.range(pc..end).next().is_some() {
                return Err(corrupt(base + pc, "Overlapping compact BGI instructions"));
            }
            let (operation, variant) = opcode::compact(code);
            let instruction = Instruction {
                id: 0,
                span: Span {
                    offset: (base + pc) as u64,
                    size: (end - pc) as u64,
                },
                source_line: None,
                opcode: Opcode {
                    namespace: "bgi.compact".into(),
                    code: opcode,
                    operation,
                    variant,
                    native_mnemonic: None,
                },
                args,
                attributes: Vec::new(),
            };
            instructions.insert(pc, instruction);
            pc = end;
            if bytes[pc..data_start.max(pc)].iter().all(|&byte| byte == 0) {
                break;
            }
        }
    }
    let mut instructions: Vec<_> = instructions.into_values().collect();
    for (id, instruction) in instructions.iter_mut().enumerate() {
        instruction.id = id as u64;
    }
    let mut sections = vec![
        section("header", 0, &data[..base]),
        section("program", base, bytes),
    ];
    if base + length < data.len() {
        sections.push(section("trailing", base + length, &data[base + length..]));
    }
    Ok(Script {
        ir_version: VERSION,
        format: "script/bgi/compact".into(),
        format_version: 1,
        sections,
        instructions,
    })
}
fn text_bytes(data: &[u8], at: usize) -> usize {
    data[at..].iter().position(|&b| b == 0).map_or(0, |n| n + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;
    #[test]
    fn compact_variable_operands_references_and_data_are_lossless() -> Result<()> {
        let body = [
            0x12, 0x7f, 0x05, 14, 0, 0x03, 1, 0x7f, 2, 0x15, 9, 4, 0, 0x17, 0, 0, b'h', b'i', 0,
        ];
        let mut bytes = vec![0; 16];
        BinaryWriter::u32_le(16, &mut bytes);
        BinaryWriter::u32_le(body.len() as u32, &mut bytes[4..]);
        bytes.extend(body);
        let script = parse(&bytes)?;
        assert_eq!(script.instructions.len(), 5);
        assert!(matches!(
            script.instructions[0].args[0].value,
            Value::Integer(-1)
        ));
        assert!(matches!(script.instructions[1].args[1].value,Value::Text(ref text) if text=="hi"));
        assert!(matches!(
            script.instructions[2].args[1].value,
            Value::Integer(-1)
        ));
        assert_eq!(
            script.instructions[3].span,
            Span {
                offset: 25,
                size: 4
            }
        );
        assert_eq!(
            script
                .sections
                .iter()
                .flat_map(|s| s.raw.iter().copied())
                .collect::<Vec<_>>(),
            bytes
        );
        let end = bytes.len() - 1;
        assert!(parse(&bytes[..end]).is_err());
        Ok(())
    }
}
