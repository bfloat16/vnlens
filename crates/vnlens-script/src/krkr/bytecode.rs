//! TJS2100 tTJSByteCodeLoader layout: LE constant pools, OBJS records, signed
//! 16-bit VM words and typed constant references. tTJSInterCodeContext opcodes
//! determine instruction widths, including expanded call argument lists.
use super::{bad, opcode};
use crate::ir::*;
use std::collections::BTreeMap;
use vnlens_core::{Error, Result};
use vnlens_io::BinaryReader;
fn align(r: &mut BinaryReader<'_>) -> Result<()> {
    r.read_bytes((4 - r.position() % 4) % 4)?;
    Ok(())
}
fn array<'a>(r: &mut BinaryReader<'a>, width: usize) -> Result<&'a [u8]> {
    let size = (r.read_u32_le()? as usize)
        .checked_mul(width)
        .ok_or_else(|| bad(r.position(), "TJS array size overflow"))?;
    Ok(r.read_bytes(size)?)
}
fn chunk<'a>(r: &mut BinaryReader<'a>, tag: &[u8]) -> Result<&'a [u8]> {
    if r.read_bytes(4)? != tag {
        return Err(bad(r.position(), "Invalid TJS chunk tag"));
    }
    let n = (r.read_u32_le()? as usize)
        .checked_sub(8)
        .ok_or_else(|| bad(r.position(), "Invalid TJS chunk length"))?;
    Ok(r.read_bytes(n)?)
}
fn pools(bytes: &[u8]) -> Result<[Vec<Value>; 11]> {
    let mut pools: [Vec<Value>; 11] = std::array::from_fn(|_| Vec::new());
    let mut r = BinaryReader::new(bytes);
    for (kind, width) in [(6, 1), (7, 2), (8, 4), (9, 8), (5, 8)] {
        let mut values = BinaryReader::new(array(&mut r, width)?);
        while values.remaining() != 0 {
            pools[kind].push(match kind {
                6 => Value::Integer(i64::from(values.read_u8()? as i8)),
                7 => Value::Integer(i64::from(values.read_u16_le()? as i16)),
                8 => Value::Integer(i64::from(values.read_u32_le()? as i32)),
                9 => Value::Integer(values.read_i64_le()?),
                _ => Value::Float64Bits(values.read_u64_le()?),
            });
        }
        align(&mut r)?;
    }
    let strings = r.read_u32_le()?;
    for _ in 0..strings {
        let mut chars = BinaryReader::new(array(&mut r, 2)?);
        let mut words = Vec::new();
        while chars.remaining() != 0 {
            words.push(chars.read_u16_le()?);
        }
        pools[3].push(Value::Text(
            String::from_utf16(&words).map_err(|_| bad(r.position(), "Invalid TJS UTF-16"))?,
        ));
        align(&mut r)?;
    }
    let octets = r.read_u32_le()?;
    for _ in 0..octets {
        pools[4].push(Value::Bytes(array(&mut r, 1)?.to_vec()));
        align(&mut r)?;
    }
    if r.remaining() != 0 {
        return Err(bad(r.position(), "Trailing TJS constants"));
    }
    Ok(pools)
}
pub(super) fn string_constants(bytes: &[u8]) -> Result<Vec<String>> {
    let mut reader = BinaryReader::new_at(bytes, 12)?;
    let mut constants = pools(chunk(&mut reader, b"DATA")?)?;
    Ok(std::mem::take(&mut constants[3])
        .into_iter()
        .filter_map(|value| {
            if let Value::Text(text) = value {
                Some(text)
            } else {
                None
            }
        })
        .collect())
}
pub(super) fn parse(bytes: &[u8]) -> Result<Script> {
    let mut r = BinaryReader::new(bytes);
    if r.read_bytes(8)? != b"TJS2100\0" {
        return Err(Error::Unsupported("TJS bytecode version".into()));
    }
    if r.read_u32_le()? as usize != bytes.len() {
        return Err(bad(8, "TJS file length mismatch"));
    }
    let pools = pools(chunk(&mut r, b"DATA")?)?;
    let objects = chunk(&mut r, b"OBJS")?;
    let objects_base = r.position() - objects.len();
    if r.remaining() != 0 {
        return Err(bad(r.position(), "Trailing TJS file data"));
    }
    let mut r = BinaryReader::new(objects);
    let top = r.read_u32_le()?;
    let count = r.read_u32_le()?;
    if top != u32::MAX && top >= count {
        return Err(bad(objects_base, "TJS top-level index out of range"));
    }
    let mut script = Script {
        ir_version: VERSION,
        format: "TJS2".into(),
        format_version: 100,
        sections: vec![Section {
            name: "file".into(),
            span: Span {
                offset: 0,
                size: bytes.len() as u64,
            },
            raw: bytes.to_vec(),
        }],
        instructions: Vec::new(),
    };
    for object in 0..count {
        if r.read_bytes(4)? != b"TJS2" {
            return Err(bad(r.position() + objects_base, "Invalid TJS object tag"));
        }
        let size = r.read_u32_le()? as usize;
        let base = objects_base + r.position();
        let mut o = BinaryReader::new(r.read_bytes(size)?);
        let mut header = [0u32; 12];
        for value in &mut header {
            *value = o.read_u32_le()?;
        }
        let source_count = o.read_u32_le()? as usize;
        let source_bytes = source_count
            .checked_mul(4)
            .ok_or_else(|| bad(base, "TJS source map size overflow"))?;
        let code_positions = o.read_bytes(source_bytes)?;
        let source_positions = o.read_bytes(source_bytes)?;
        let source: BTreeMap<_, _> = code_positions
            .as_chunks::<4>()
            .0
            .iter()
            .zip(source_positions.as_chunks::<4>().0)
            .map(|(a, b)| (BinaryReader::u32_le(a) as usize, BinaryReader::u32_le(b)))
            .collect();
        let code_bytes = array(&mut o, 2)?;
        let code_base = base + o.position() - code_bytes.len();
        let code = code_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| BinaryReader::u16_le(b) as i16)
            .collect::<Vec<_>>();
        align(&mut o)?;
        let data = array(&mut o, 4)?;
        let mut values = Vec::new();
        for pair in data.as_chunks::<4>().0 {
            let kind = BinaryReader::u16_le(pair);
            let index = BinaryReader::u16_le(&pair[2..]);
            let value = match kind {
                3..=9 => pools[usize::from(kind)]
                    .get(usize::from(index))
                    .cloned()
                    .ok_or_else(|| bad(base, "TJS constant index out of range"))?,
                _ => Value::Group(vec![
                    operand(ArgName::Type, 0, 0, Value::Unsigned(u64::from(kind))),
                    operand(
                        ArgName::Index,
                        0,
                        0,
                        Value::Integer(i64::from(index as i16)),
                    ),
                ]),
            };
            values.push(value);
        }
        array(&mut o, 4)?;
        array(&mut o, 8)?;
        if o.remaining() != 0 {
            return Err(bad(base + o.position(), "Trailing TJS object data"));
        }
        let mut pc = 0;
        while pc < code.len() {
            let opcode = code[pc];
            let n = opcode::width(&code, pc)?;
            let end = pc
                .checked_add(n)
                .ok_or_else(|| bad(code_base, "TJS instruction overflow"))?;
            let words = code
                .get(pc..end)
                .ok_or_else(|| bad(code_base + pc * 2, "Truncated TJS instruction"))?;
            let mut args = Vec::new();
            for (i, &word) in words.iter().enumerate().skip(1) {
                let mut value = Value::Integer(i64::from(word));
                let mut name = ArgName::Unknown(i as u64);
                let constant_index = match opcode {
                    1 | 104..=106 | 111 => Some(2),
                    19 | 23 | 84 | 100 | 103 | 110 | 116 => Some(3),
                    _ => None,
                };
                if constant_index == Some(i) {
                    value =
                        values
                            .get(usize::try_from(word).map_err(|_| {
                                bad(code_base + pc * 2, "Negative TJS constant index")
                            })?)
                            .cloned()
                            .ok_or_else(|| {
                                bad(code_base + pc * 2, "TJS local constant index out of range")
                            })?;
                    name = ArgName::Value;
                }
                if matches!(opcode, 15..=17 | 120) && i == 1 {
                    let target = pc
                        .checked_add_signed(isize::from(word))
                        .filter(|&v| v < code.len())
                        .ok_or_else(|| bad(code_base + pc * 2, "TJS branch target out of range"))?;
                    value = Value::CodeAddress((code_base + target * 2) as u64);
                    name = ArgName::Target;
                }
                args.push(operand(name, code_base + (pc + i) * 2, 2, value));
            }
            let (operation, variant) = opcode::operation(opcode);
            let mut attributes = vec![
                Attribute {
                    name: "object".into(),
                    value: u64::from(object),
                },
                Attribute {
                    name: "context".into(),
                    value: u64::from(header[2]),
                },
            ];
            if let Some((_, &position)) = source.range(..=pc).next_back() {
                attributes.push(Attribute {
                    name: "source_offset".into(),
                    value: u64::from(position),
                });
            }
            script.instructions.push(Instruction {
                id: script.instructions.len() as u64,
                span: Span {
                    offset: (code_base + pc * 2) as u64,
                    size: (n * 2) as u64,
                },
                source_line: None,
                opcode: Opcode {
                    operation,
                    variant,
                    namespace: "krkr/tjs2".into(),
                    code: opcode as u16 as u32,
                    native_mnemonic: opcode::mnemonic(opcode),
                },
                args,
                attributes,
            });
            pc = end;
        }
    }
    if r.remaining() != 0 {
        return Err(bad(objects_base + r.position(), "Trailing TJS objects"));
    }
    Ok(script)
}
fn operand(name: ArgName, offset: usize, size: usize, value: Value) -> Arg {
    Arg {
        name,
        native_name: None,
        span: Span {
            offset: offset as u64,
            size: size as u64,
        },
        value,
        attributes: Vec::new(),
    }
}

#[cfg(test)]
#[path = "../../tests/krkr/bytecode.rs"]
mod tests;
