//! SPT's unit is an LE u32 word. Records start with length, family, opcode.
//! The header's words 4/5 and 6/7 are counts and absolute word offsets of
//! message/resource string-pointer tables; word 8/9 describes labels.
//! Data records are skipped by the VM and retained verbatim in the IR.
use super::{choice, control_flow, effect, expression, opcode, record, text};
use crate::ir::{self, Arg, ArgName as A, Attribute, Instruction, Script, Section, Span, Value};
use nvlens_core::{Error, ResourceResolver, Result};
use nvlens_io::{BinaryIo, BinaryReader};
use std::{borrow::Cow, collections::BTreeMap};

pub(super) fn decode(data: &[u8]) -> Result<Cow<'_, [u8]>> {
    BinaryReader::new(data).read_bytes(64)?;
    if data.get(48..58) == Some(b"SPTHEADER0") {
        return Ok(Cow::Borrowed(data));
    }
    let mut bytes = data.to_vec();
    nvlens_crypto::cipher::xor::apply_u32_key(&mut bytes, &[255; 4]);
    if bytes.get(48..58) != Some(b"SPTHEADER0") {
        return Err(Error::UnknownScheme(Some(
            "Unrecognized SystemNNN SPT encoding".into(),
        )));
    }
    Ok(Cow::Owned(bytes))
}
fn corrupt(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
pub(super) fn byte_offset(word: u32) -> Result<usize> {
    usize::try_from(u64::from(word) * 4).map_err(|_| corrupt(0, "SPT offset exceeds address space"))
}
pub(super) fn word(data: &[u8], index: usize) -> Result<u32> {
    let at = index
        .checked_mul(4)
        .ok_or_else(|| corrupt(0, "SPT word offset overflow"))?;
    Ok(BinaryReader::new_at(data, at)?.read_u32_le()?)
}
pub(super) fn arg(name: A, at: usize, size: usize, value: Value) -> Arg {
    Arg {
        name,
        native_name: None,
        span: Span {
            offset: at as u64,
            size: size as u64,
        },
        value,
        attributes: Vec::new(),
    }
}
pub(super) fn unsigned(name: A, at: usize, value: u32) -> Arg {
    arg(name, at, 4, Value::Unsigned(u64::from(value)))
}

pub(super) struct Tables<'a> {
    data: &'a [u8],
    messages: &'a [u8],
    pub(super) resources: &'a [u8],
    labels: &'a [u8],
}
impl Tables<'_> {
    pub(super) fn string(&self, table: &[u8], index: u32, name: A, at: usize) -> Result<Arg> {
        let pointer = word(table, index as usize)?;
        let start = byte_offset(pointer)?;
        let mut r = BinaryReader::new_at(self.data, start)?;
        while r.read_u8()? != 0 {}
        let bytes = &self.data[start..r.position() - 1];
        let (decoded, _, errors) = encoding_rs::SHIFT_JIS.decode(bytes);
        let value = if errors {
            Value::Bytes(bytes.to_vec())
        } else {
            Value::Text(decoded.into_owned())
        };
        let mut value = arg(name, at, 4, value);
        value.attributes = vec![
            Attribute {
                name: "index".into(),
                value: u64::from(index),
            },
            Attribute {
                name: "data_offset".into(),
                value: start as u64,
            },
        ];
        Ok(value)
    }
}
fn table(data: &[u8], count_field: usize, offset_field: usize) -> Result<&[u8]> {
    let size = byte_offset(word(data, count_field)?)?;
    let offset = byte_offset(word(data, offset_field)?)?;
    Ok(BinaryReader::new_at(data, offset)?.read_bytes(size)?)
}

pub(super) fn parse(data: &[u8], resources: Option<&dyn ResourceResolver>) -> Result<Script> {
    let decoded = decode(data)?;
    let data = decoded.as_ref();
    if !data.len().is_multiple_of(4) {
        return Err(BinaryIo::unexpected_eof("Partial SPT word").into());
    }
    let mut r = BinaryReader::new(data);
    let header_words = r.read_u32_le()?;
    if header_words < 19 || r.read_u32_le()? != 0x66660001 || r.read_u32_le()? != 0x55550001 {
        return Err(Error::InvalidFormat);
    }
    BinaryReader::new(data).read_bytes(byte_offset(header_words)?)?;
    let tables = Tables {
        data,
        messages: table(data, 4, 5)?,
        resources: table(data, 6, 7)?,
        labels: table(data, 8, 9)?,
    };
    let mut named_tables = BTreeMap::new();
    let mut instructions = Vec::new();
    let mut r = BinaryReader::new(data);
    while r.remaining() != 0 {
        let at = r.position();
        let size = byte_offset(r.read_u32_le()?)?;
        if size < 12 {
            return Err(corrupt(at, "SPT record is shorter than its header"));
        }
        let family = r.read_u32_le()?;
        let code = r.read_u32_le()?;
        let body = r.read_bytes(size - 12)?;
        BinaryReader::new(body).read_bytes(opcode::minimum_words(family, code) * 4)?;
        if opcode::has_argument_count(family, code) {
            let count = byte_offset(word(body, 0)?)?;
            BinaryReader::new_at(body, 4)?.read_bytes(count)?;
        }
        let first = if body.len() >= 8 {
            Some(word(body, 1)?)
        } else {
            None
        };
        let second = if body.len() >= 12 {
            Some(word(body, 2)?)
        } else {
            None
        };
        let mut op = opcode::instruction(family, code, first, second);
        let mut args = Vec::new();
        match family {
            0x66660001 => {
                (op.variant, args) = record::parse(data, body, at, code)?;
            }
            0x66660003 | 0x66660004 => {
                let table_name = if family == 0x66660003 {
                    "command.xtx"
                } else {
                    "function.xtx"
                };
                if let Some(resolver) = resources {
                    if !named_tables.contains_key(table_name) {
                        let names = resolver
                            .read_resource(table_name)?
                            .map(|data| text::decode(&data))
                            .transpose()?;
                        named_tables.insert(
                            table_name,
                            names.map(|text| {
                                text.lines()
                                    .map(|line| {
                                        line.split(',').next().unwrap_or_default().to_owned()
                                    })
                                    .collect::<Vec<_>>()
                            }),
                        );
                    }
                    op.native_mnemonic = named_tables
                        .get(table_name)
                        .and_then(Option::as_ref)
                        .and_then(|names| names.get(code as usize))
                        .cloned();
                }
                if let Some(name) = op.native_mnemonic.as_deref() {
                    op.operation = opcode::named_operation(family, name);
                }
                let mut values = BinaryReader::new(body);
                let count = values.read_u32_le()?;
                args.push(unsigned(A::ArgumentCount, at + 12, count));
                for i in 0..count {
                    let name = opcode::named_argument(family, op.native_mnemonic.as_deref(), i);
                    args.push(expression::parse(&mut values, at + 12, name, data)?);
                }
                if family == 0x66660003 {
                    // Execute stores the final command word as its return code.
                    let tail = values
                        .remaining()
                        .checked_sub(4)
                        .ok_or_else(|| corrupt(at, "SPT command return code is missing"))?;
                    let mut extra = BinaryReader::new(values.read_bytes(tail)?);
                    let base = at + 12 + values.position() - tail;
                    while extra.remaining() != 0 {
                        let position = base + extra.position();
                        args.push(unsigned(
                            A::Unknown(((position - at - 12) / 4) as u64),
                            position,
                            extra.read_u32_le()?,
                        ));
                    }
                    let position = at + 12 + values.position();
                    args.push(unsigned(A::ReturnCode, position, values.read_u32_le()?));
                } else {
                    append_unknown(&mut values, at + 12, &mut args)?;
                }
            }
            0x66660005 => {
                let mut values = BinaryReader::new(body);
                let value = expression::parse(&mut values, at + 12, A::Command, data)?;
                if let Value::Expression(tokens) = &value.value
                    && let Some(last) = tokens.last()
                {
                    op.operation = last.opcode.operation;
                    op.variant = last.opcode.variant;
                }
                args.push(value);
                append_unknown(&mut values, at + 12, &mut args)?;
            }
            0x66660002 if matches!(code, 0x55560002 | 0x55560003 | 0x55560011) => {
                let mut values = BinaryReader::new(body);
                args.push(expression::parse(&mut values, at + 12, A::Condition, data)?);
                append_unknown(&mut values, at + 12, &mut args)?;
            }
            0x66660006 if code == 0x22220006 => {
                args = choice::parse(body, at + 12, &tables)?;
            }
            0x66660007 if code == 0x33330016 => {
                args.push(unsigned(A::ArgumentCount, at + 12, word(body, 0)?));
                args.push(unsigned(A::Index, at + 16, word(body, 1)?));
                for (name, first) in [(A::Source, 2), (A::Destination, 6)] {
                    let mut region = Vec::new();
                    for (i, field) in [A::OffsetX, A::OffsetY, A::Width, A::Height]
                        .into_iter()
                        .enumerate()
                    {
                        region.push(arg(
                            field,
                            at + 12 + (first + i) * 4,
                            4,
                            Value::Integer(i64::from(word(body, first + i)? as i32)),
                        ));
                    }
                    args.push(arg(name, at + 12 + first * 4, 16, Value::Group(region)));
                }
                let mut tail = BinaryReader::new_at(body, 40)?;
                append_unknown(&mut tail, at + 12, &mut args)?;
            }
            _ => {
                for (i, bytes) in body.as_chunks::<4>().0.iter().enumerate() {
                    let value = BinaryReader::u32_le(bytes);
                    let position = at + 12 + i * 4;
                    let count = word(body, 0)?;
                    let effect_field = family == 0x66660007
                        && code == 0x33330013
                        && i >= 3
                        && i as u64 <= u64::from(count);
                    let name = if effect_field {
                        effect::argument(word(body, 2)?, i - 3)
                    } else {
                        opcode::argument(family, code, i, first, count)
                    };
                    let item = if i == 0
                        && ((family == 0x66660006 && (0x22220001..=0x22220003).contains(&code))
                            || (family == 0x66660007 && code == 0x33330042))
                    {
                        tables.string(tables.messages, value, name, position)?
                    } else if value != u32::MAX
                        && ((family == 0x66660007
                            && matches!(
                                code,
                                0x33330008 | 0x33330015 | 0x3333001f | 0x33330050 | 0x33330051
                            )
                            && i == 1)
                            || (family == 0x66660002
                                && matches!(code, 0x5556000a | 0x55560015 | 0x55560016)
                                && i == 0))
                    {
                        tables.string(tables.resources, value, name, position)?
                    } else if family == 0x66660002 && code == 0x55560009 && i == 0 {
                        let target = byte_offset(word(tables.labels, value as usize)?)?;
                        args.push(unsigned(A::LabelId, position, value));
                        arg(
                            A::ResolvedTarget,
                            position,
                            0,
                            Value::CodeAddress(target as u64),
                        )
                    } else if family == 0x66660002
                        && ((code == 0x55560020 && i == 0) || (code == 0xa000007b && i == 0))
                    {
                        let target = byte_offset(value)?;
                        let target = if code == 0xa000007b {
                            at.checked_add(target)
                                .ok_or_else(|| corrupt(at, "SPT block end overflow"))?
                        } else {
                            target
                        };
                        let mut item = arg(name, position, 4, Value::CodeAddress(target as u64));
                        item.attributes.push(Attribute {
                            name: "word_offset".into(),
                            value: u64::from(value),
                        });
                        item
                    } else if name != A::Flags
                        && !matches!(name, A::Unknown(_))
                        && (effect_field || opcode::signed_argument(family, code, i, first))
                    {
                        arg(name, position, 4, Value::Integer(i64::from(value as i32)))
                    } else {
                        unsigned(name, position, value)
                    };
                    args.push(item);
                }
            }
        }
        instructions.push(Instruction {
            id: instructions.len() as u64,
            span: Span {
                offset: at as u64,
                size: size as u64,
            },
            source_line: None,
            opcode: op,
            args,
            attributes: Vec::new(),
        });
    }
    control_flow::resolve(data, &mut instructions)?;
    Ok(Script {
        ir_version: ir::VERSION,
        format: "spt/systemnnn".into(),
        format_version: 0,
        sections: vec![Section {
            name: "decoded".into(),
            span: Span {
                offset: 0,
                size: data.len() as u64,
            },
            raw: decoded.into_owned(),
        }],
        instructions,
    })
}
fn append_unknown(r: &mut BinaryReader<'_>, base: usize, args: &mut Vec<Arg>) -> Result<()> {
    while r.remaining() != 0 {
        let at = base + r.position();
        args.push(unsigned(
            A::Unknown((r.position() / 4) as u64),
            at,
            r.read_u32_le()?,
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/systemnnn/spt.rs"]
mod tests;
