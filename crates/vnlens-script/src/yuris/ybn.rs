//! YSTB 0x1EE disassembly, verified at 0x452299 (sections/instructions),
//! 0x429E7D (12-byte args), 0x446044 (conditional targets), and 0x45D83C
//! (YSCM command definitions). The four XOR sections restart independently.

use super::{attribute, corrupt, expression, opcode, operand, section, tables};
use crate::ir::StorageOperation;
use crate::ir::*;
use vnlens_core::{Error, ResourceResolver, Result};
use vnlens_io::BinaryReader;

fn sections(data: &[u8]) -> Result<(usize, Vec<std::ops::Range<usize>>)> {
    let mut reader = BinaryReader::new(data);
    if reader.read_bytes(4)? != b"YSTB" {
        return Err(Error::InvalidFormat);
    }
    let version = reader.read_u32_le()?;
    if version != 0x1ee {
        return Err(Error::Unsupported(format!("YSTB version 0x{version:X}")));
    }
    let count = reader.read_u32_le()? as usize;
    let mut start = 32usize;
    let mut sections = Vec::with_capacity(4);
    for _ in 0..4 {
        let size = reader.read_u32_le()? as usize;
        let end = start
            .checked_add(size)
            .filter(|&end| end <= data.len())
            .ok_or_else(|| corrupt(start, "YSTB section exceeds file"))?;
        sections.push(start..end);
        start = end;
    }
    reader.read_u32_le()?;
    if start != data.len() {
        return Err(corrupt(start, "YSTB section sizes do not cover file"));
    }
    if count.checked_mul(4) != Some(sections[0].len())
        || sections[3].len() != sections[0].len()
        || !sections[1].len().is_multiple_of(12)
    {
        return Err(corrupt(
            8,
            "YSTB instruction, operand, or source-line table size mismatch",
        ));
    }
    Ok((count, sections))
}

pub fn decrypt_ystb(data: &mut [u8], key: &[u8; 4]) -> Result<()> {
    let (_, ranges) = sections(data)?;
    for range in ranges {
        vnlens_crypto::cipher::xor::apply_u32_key(&mut data[range], key);
    }
    Ok(())
}

pub(super) fn disassemble(data: &[u8], resources: Option<&dyn ResourceResolver>) -> Result<Script> {
    let mut header = BinaryReader::new(data);
    let magic = header.read_bytes(4)?;
    let version = header.read_u32_le()?;
    if version != 0x1ee {
        return Err(Error::Unsupported(format!("YBN version 0x{version:X}")));
    }
    let mut script = Script {
        ir_version: VERSION,
        format: "ybn/yuris".into(),
        format_version: version,
        sections: Vec::new(),
        instructions: Vec::new(),
    };
    if magic != b"YSTB" {
        return tables::disassemble(data, script);
    }
    let (count, ranges) = sections(data)?;
    script.sections.push(section("header", data, 0..32));
    for (name, range) in ["instructions", "args", "data", "source_lines"]
        .iter()
        .zip(&ranges)
    {
        script.sections.push(section(name, data, range.clone()));
    }
    let definitions = if let Some(resources) = resources {
        resources
            .read_resource("ysbin/ysc.ybn")?
            .map(|bytes| tables::commands(&bytes).map(|v| v.0))
            .transpose()?
    } else {
        None
    };
    let mut code = BinaryReader::new(&data[ranges[0].clone()]);
    let mut params = BinaryReader::new(&data[ranges[1].clone()]);
    let values = &data[ranges[2].clone()];
    let mut lines = BinaryReader::new(&data[ranges[3].clone()]);
    let mut labels = None;
    script.instructions.reserve(count);
    for id in 0..count {
        let op = code.read_u8()?;
        let argc = code.read_u8()?;
        let flags = code.read_u8()?;
        let reserved = code.read_u8()?;
        let definition = definitions
            .as_ref()
            .and_then(|defs| defs.get(usize::from(op)));
        let mut instruction = Instruction {
            id: id as u64,
            span: Span {
                offset: (32 + id * 4) as u64,
                size: 4,
            },
            source_line: Some(lines.read_u32_le()?),
            opcode: opcode::opcode(u32::from(op), definition.map(|d| d.name.clone())),
            args: Vec::with_capacity(usize::from(argc)),
            attributes: vec![attribute("flags", flags), attribute("reserved", reserved)],
        };
        for arg_index in 0..argc {
            let start = ranges[1].start + params.position();
            let arg = params.read_u8()?;
            let flags = params.read_u8()?;
            let ty = params.read_u8()?;
            let operator = params.read_u8()?;
            let length = params.read_u32_le()?;
            let offset = params.read_u32_le()?;
            let span = Span {
                offset: start as u64,
                size: 12,
            };
            let is_control = (matches!(op, 11 | 45 | 46 | 56) && arg_index > 0) || op == 79;
            let argument = definition.and_then(|d| d.arguments.get(usize::from(arg)));
            if op == 54 && arg_index == 0 {
                let operation = match operator {
                    0 => Qualifier::Assign,
                    1 => Qualifier::AddAssign,
                    2 => Qualifier::SubtractAssign,
                    3 => Qualifier::MultiplyAssign,
                    4 => Qualifier::DivideAssign,
                    5 => Qualifier::RemainderAssign,
                    6 => Qualifier::BitAndAssign,
                    7 => Qualifier::BitOrAssign,
                    8 => Qualifier::BitXorAssign,
                    _ => Qualifier::UnknownUpdate,
                };
                instruction.opcode.operation = Operation::Storage(StorageOperation::Store);
                instruction.opcode.variant = Some(operation);
            }
            let name = opcode::argument(u32::from(op), arg, arg_index, is_control);
            let value = if is_control {
                if op != 79 && length as usize > count {
                    return Err(corrupt(
                        start + 4,
                        "Control target exceeds instruction stream",
                    ));
                }
                Value::Group(vec![
                    operand(
                        if op == 79 {
                            ArgName::Id
                        } else {
                            ArgName::Descriptor
                        },
                        Span {
                            offset: start as u64,
                            size: 4,
                        },
                        Value::Unsigned(u64::from(BinaryReader::u32_le(&data[start..]))),
                    ),
                    operand(
                        if op == 79 {
                            ArgName::Metadata
                        } else {
                            ArgName::Target
                        },
                        Span {
                            offset: start as u64 + 4,
                            size: 4,
                        },
                        if op == 79 {
                            Value::Unsigned(u64::from(length))
                        } else {
                            Value::InstructionTarget(u64::from(length))
                        },
                    ),
                    operand(
                        ArgName::DataOffset,
                        Span {
                            offset: start as u64 + 8,
                            size: 4,
                        },
                        Value::Unsigned(u64::from(offset)),
                    ),
                ])
            } else {
                let end = (offset as usize)
                    .checked_add(length as usize)
                    .filter(|&end| end <= values.len())
                    .ok_or_else(|| {
                        corrupt(
                            start,
                            "Arg data range exceeds value section; script may still be encrypted",
                        )
                    })?;
                let raw = &values[offset as usize..end];
                let address = (ranges[2].start + offset as usize) as u64;
                if ty == 0 && matches!(op, 106 | 110) {
                    Value::Text(expression::text(raw, address)?)
                } else if ty <= 4 {
                    Value::Expression(expression::decode(raw, address)?)
                } else {
                    Value::Bytes(raw.to_vec())
                }
            };
            let mut attributes = vec![
                attribute("id", arg),
                attribute("flags", flags),
                attribute("type", ty),
                attribute("operator", operator),
                attribute("length", length),
                attribute("offset", offset),
            ];
            if !is_control && let Some(argument) = argument {
                attributes.push(attribute("declared_kind", argument.kind));
                attributes.push(attribute("conversion_rule", argument.rule));
            }
            instruction.args.push(Arg {
                name,
                native_name: argument.map(|argument| argument.name.clone()),
                span,
                value,
                attributes,
            });
            if matches!(op, 43 | 44)
                && arg == 0
                && let Some(Value::Expression(tokens)) = instruction.args.last().map(|p| &p.value)
                && let [token] = tokens.as_slice()
                && token.opcode.code == u32::from(b'M')
                && let Some(Arg {
                    value: Value::Text(name),
                    ..
                }) = token.args.first()
                && let Some(resources) = resources
            {
                if labels.is_none() {
                    labels = Some(
                        resources
                            .read_resource("ysbin/ysl.ybn")?
                            .map(|bytes| tables::labels(&bytes))
                            .transpose()?,
                    );
                }
                if let Some(Some(labels)) = &labels
                    && let Some(label) = labels.iter().find(|label| label.name == *name)
                {
                    instruction.args.push(operand(
                        ArgName::ResolvedTarget,
                        span,
                        Value::ResourceInstructionTarget {
                            resource: format!("ysbin/yst{:05}.ybn", label.script),
                            instruction: u64::from(label.instruction),
                            symbol: label.name.clone(),
                        },
                    ));
                }
            }
        }
        script.instructions.push(instruction);
    }
    if params.remaining() != 0 {
        return Err(corrupt(
            ranges[1].start + params.position(),
            "Unclaimed operand records",
        ));
    }
    Ok(script)
}

#[cfg(test)]
#[path = "../../tests/yuris/ybn.rs"]
mod tests;
