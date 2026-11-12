//! TJS2100 tTJSByteCodeLoader layout: LE constant pools, OBJS records, signed
//! 16-bit VM words and typed constant references. tTJSInterCodeContext opcodes
//! determine instruction widths, including expanded call argument lists.
use super::{bad, object::Object, opcode, operands};
use crate::ir::*;
use std::collections::BTreeSet;
use vnlens_core::{Error, Result};
use vnlens_io::BinaryReader;
fn align(r: &mut BinaryReader<'_>) -> Result<()> {
    r.read_bytes((4 - r.position() % 4) % 4)?;
    Ok(())
}
pub(super) fn array<'a>(r: &mut BinaryReader<'a>, width: usize) -> Result<&'a [u8]> {
    let size = (r.read_u32_le()? as usize)
        .checked_mul(width)
        .ok_or_else(|| bad(r.position(), "TJS array size overflow"))?;
    Ok(r.read_bytes(size)?)
}
fn chunk<'a>(r: &mut BinaryReader<'a>, tag: &[u8]) -> Result<&'a [u8]> {
    if r.read_bytes(4)? != tag {
        return Err(bad(r.position() - 4, "Invalid TJS chunk tag"));
    }
    let n = (r.read_u32_le()? as usize)
        .checked_sub(8)
        .ok_or_else(|| bad(r.position(), "Invalid TJS chunk length"))?;
    Ok(r.read_bytes(n)?)
}
fn pools(bytes: &[u8], base: usize) -> Result<[Vec<Value>; 11]> {
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
        pools[3]
            .push(Value::Text(String::from_utf16(&words).map_err(|_| {
                bad(base + r.position(), "Invalid TJS UTF-16")
            })?));
        align(&mut r)?;
    }
    let octets = r.read_u32_le()?;
    for _ in 0..octets {
        pools[4].push(Value::Bytes(array(&mut r, 1)?.to_vec()));
        align(&mut r)?;
    }
    if r.remaining() != 0 {
        return Err(bad(base + r.position(), "Trailing TJS constants"));
    }
    Ok(pools)
}
pub(super) fn string_constants(bytes: &[u8]) -> Result<Vec<String>> {
    let mut reader = BinaryReader::new_at(bytes, 12)?;
    let data = chunk(&mut reader, b"DATA")?;
    let mut constants = pools(data, reader.position() - data.len())?;
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
    let data = chunk(&mut r, b"DATA")?;
    let pools = pools(data, r.position() - data.len())?;
    let object_bytes = chunk(&mut r, b"OBJS")?;
    let objects_base = r.position() - object_bytes.len();
    if r.remaining() != 0 {
        return Err(bad(r.position(), "Trailing TJS file data"));
    }
    let mut r = BinaryReader::new(object_bytes);
    let top = r.read_u32_le()? as i32;
    let count = r.read_u32_le()?;
    if top >= 0 && top as u32 >= count {
        return Err(bad(objects_base, "TJS top-level index out of range"));
    }
    let mut objects = Vec::new();
    for _ in 0..count {
        if r.read_bytes(4)? != b"TJS2" {
            return Err(bad(
                objects_base + r.position() - 4,
                "Invalid TJS object tag",
            ));
        }
        let size = r.read_u32_le()? as usize;
        let base = objects_base + r.position();
        objects.push(Object::read(
            r.read_bytes(size)?,
            base,
            count as usize,
            &pools[3],
        )?);
    }
    if r.remaining() != 0 {
        return Err(bad(objects_base + r.position(), "Trailing TJS objects"));
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
    push_record(
        &mut script,
        "header",
        objects_base,
        8,
        vec![
            operand(
                ArgName::FunctionIndex,
                objects_base,
                4,
                Value::Integer(i64::from(top)),
            ),
            operand(
                ArgName::Count,
                objects_base + 4,
                4,
                Value::Unsigned(u64::from(count)),
            ),
        ],
        Vec::new(),
    );
    for (index, object) in objects.iter().enumerate() {
        let attributes = vec![
            Attribute {
                name: "object".into(),
                value: index as u64,
            },
            Attribute {
                name: "context".into(),
                value: u64::from(object.header[2] as u32),
            },
        ];
        let mut metadata = vec![operand(
            ArgName::Index,
            object.base,
            0,
            Value::Unsigned(index as u64),
        )];
        metadata.extend(object.metadata.clone());
        let mut values = Vec::new();
        let mut constants = Vec::new();
        for (i, pair) in object.data.as_chunks::<4>().0.iter().enumerate() {
            let at = object.data_base + i * 4;
            let kind = BinaryReader::u16_le(pair) as i16;
            let pool_index = BinaryReader::u16_le(&pair[2..]) as i16;
            let value = match kind {
                0 => Value::Nil,
                // TYPE_OBJECT is always a null dispatch pointer, not an object index.
                1 => Value::Group(vec![
                    operand(ArgName::Type, at, 0, Value::Integer(1)),
                    operand(ArgName::Value, at, 0, Value::Nil),
                ]),
                2 | 10 => object_reference(pool_index, &objects, &pools[3], at + 2)?,
                3..=9 => usize::try_from(pool_index)
                    .ok()
                    .and_then(|i| pools[kind as usize].get(i))
                    .cloned()
                    .ok_or_else(|| bad(at + 2, "TJS constant pool index out of range"))?,
                _ => Value::Group(vec![
                    operand(ArgName::Unknown(0), at, 2, Value::Integer(i64::from(kind))),
                    operand(
                        ArgName::Unknown(1),
                        at + 2,
                        2,
                        Value::Integer(i64::from(pool_index)),
                    ),
                ]),
            };
            constants.push(operand(
                ArgName::Constant(i as u64),
                at,
                4,
                Value::Group(vec![
                    operand(ArgName::Type, at, 2, Value::Integer(i64::from(kind))),
                    operand(
                        ArgName::Index,
                        at + 2,
                        2,
                        Value::Integer(i64::from(pool_index)),
                    ),
                    operand(ArgName::Value, at, 0, value.clone()),
                ]),
            ));
            values.push(value);
        }
        metadata.push(operand(
            ArgName::Constants,
            object.data_base - 4,
            object.data.len() + 4,
            Value::Group(constants),
        ));
        push_record(
            &mut script,
            "object",
            object.base,
            48,
            metadata,
            attributes.clone(),
        );
        let mut pc = 0;
        let mut starts = BTreeSet::new();
        let mut targets = Vec::new();
        while pc < object.code.len() {
            starts.insert(pc);
            let at = object.code_base + pc * 2;
            let width = opcode::width(&object.code, pc, object.code_base)?;
            let words = &object.code[pc..pc + width];
            let args =
                operands::decode(words, at, pc, object.code_base, object.code.len(), &values)?;
            if matches!(words[0], 15..=17 | 120) {
                targets.push((pc, words[1]));
            }
            let (operation, variant) = opcode::operation(words[0]);
            let mut attributes = attributes.clone();
            if let Some((_, &position)) = object.source.range(..=pc).next_back() {
                attributes.push(Attribute {
                    name: "source_offset".into(),
                    value: u64::from(position),
                });
            }
            if words[0] == 87 {
                attributes.push(Attribute {
                    name: "discard_result".into(),
                    value: 1,
                });
            }
            script.instructions.push(Instruction {
                id: script.instructions.len() as u64,
                span: Span {
                    offset: at as u64,
                    size: (width * 2) as u64,
                },
                source_line: None,
                opcode: Opcode {
                    operation,
                    variant,
                    namespace: "krkr/tjs2".into(),
                    code: u32::from(words[0] as u16),
                    native_mnemonic: opcode::mnemonic(words[0]),
                },
                args,
                attributes,
            });
            pc += width;
        }
        for (pc, delta) in targets {
            let target = pc.checked_add_signed(isize::from(delta));
            if !target.is_some_and(|target| starts.contains(&target)) {
                return Err(bad(
                    object.code_base + pc * 2 + 2,
                    "TJS branch target is not an instruction boundary",
                ));
            }
        }
        if let Some(Value::Group(rows)) = object
            .metadata
            .iter()
            .find(|a| a.name == ArgName::Targets)
            .map(|a| &a.value)
        {
            for row in rows {
                if let Value::Group(fields) = &row.value
                    && let Value::Unsigned(target) = fields[0].value
                    && !starts.contains(&(target as usize))
                {
                    return Err(bad(
                        row.span.offset as usize,
                        "TJS superclass getter entry is not an instruction boundary",
                    ));
                }
            }
        }
    }
    Ok(script)
}

fn object_reference(
    index: i16,
    objects: &[Object<'_>],
    strings: &[Value],
    at: usize,
) -> Result<Value> {
    let object = usize::try_from(index)
        .ok()
        .and_then(|i| objects.get(i))
        .ok_or_else(|| bad(at, "TJS referenced object index out of range"))?;
    let mut fields = vec![
        operand(
            ArgName::FunctionIndex,
            at,
            0,
            Value::Integer(i64::from(index)),
        ),
        operand(
            ArgName::DataOffset,
            at,
            0,
            Value::DataAddress(object.base as u64),
        ),
        operand(
            ArgName::Name,
            at,
            0,
            super::object::name(object.header[1], strings, object.base + 4)?,
        ),
    ];
    if !object.code.is_empty() {
        fields.push(operand(
            ArgName::Target,
            at,
            0,
            Value::CodeAddress(object.code_base as u64),
        ));
    }
    Ok(Value::Group(fields))
}

fn push_record(
    script: &mut Script,
    name: &str,
    at: usize,
    size: usize,
    args: Vec<Arg>,
    attributes: Vec<Attribute>,
) {
    script.instructions.push(Instruction {
        id: script.instructions.len() as u64,
        span: Span {
            offset: at as u64,
            size: size as u64,
        },
        source_line: None,
        opcode: Opcode {
            operation: Operation::Data(DataOperation::Record),
            variant: Some(Qualifier::ScriptMetadata),
            namespace: "krkr/tjs2.object".into(),
            code: 0,
            native_mnemonic: Some(name.into()),
        },
        args,
        attributes,
    });
}

pub(super) fn operand(name: ArgName, offset: usize, size: usize, value: Value) -> Arg {
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
