//! YSTB 0x12C..=0x1E1 and 0x1E6..=0x22B disassembly. The four-section layout is shared by
//! loaders 0x43A1BD (0x12C), 0x4417A5 (0x1C6), 0x442705 (0x1D0),
//! 0x4495BD (0x1DA), 0x449AC9 (0x1DC), and
//! loaders 0x44A601 (0x1DF), 0x4503F5 (0x1E0), 0x45071D (0x1E6),
//! 0x451E8D (0x1E1), 0x451715 (0x1ED), 0x452299 (0x1EE), and 0x45124D (0x22B).
//! 0x429E7D (12-byte args), 0x446044 (conditional targets), and 0x45D83C
//! (0x1EE command definitions). The 0x22B command table is loaded at
//! 0x463550. Integers are little-endian; the four XOR sections restart
//! independently. The companion YSCM supplies command identities independently
//! of version-specific numbering; raw opcodes remain intact in the IR.

use super::{attribute, corrupt, expression, opcode, operand, section, tables, ystb::sections};
use crate::ir::StorageOperation;
use crate::ir::*;
use vnlens_core::{Error, ResourceResolver, Result};
use vnlens_io::BinaryReader;

pub(super) fn disassemble(data: &[u8], resources: Option<&dyn ResourceResolver>) -> Result<Script> {
    let mut header = BinaryReader::new(data);
    let magic = header.read_bytes(4)?;
    let version = header.read_u32_le()?;
    if !matches!(version, 0x12c..=0x1e1 | 0x1e6..=0x22b) {
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
            .map(|bytes| tables::commands(&bytes, None).map(|v| v.0))
            .transpose()?
    } else {
        None
    };
    if definitions.is_none() && !matches!(version, 0x1ee | 0x22b) {
        return Err(Error::Unsupported(
            "This YSTB revision requires its ysbin/ysc.ybn command table".into(),
        ));
    }
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
        let semantic_op =
            opcode::semantic_code(version, u32::from(op), definition.map(|d| d.name.as_str()));
        let mut instruction = Instruction {
            id: id as u64,
            span: Span {
                offset: (32 + id * 4) as u64,
                size: 4,
            },
            source_line: Some(lines.read_u32_le()?),
            opcode: opcode::opcode(
                u32::from(op),
                semantic_op,
                definition.map(|d| d.name.clone()),
            ),
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
            let is_control = (matches!(semantic_op, Some(11 | 45 | 46 | 56)) && arg_index > 0)
                || semantic_op == Some(79);
            let argument = definition.and_then(|d| d.arguments.get(usize::from(arg)));
            if semantic_op == Some(54) && arg_index == 0 {
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
            let name = opcode::argument(semantic_op, arg, arg_index, is_control);
            let value = if is_control {
                if semantic_op != Some(79) && length as usize > count {
                    return Err(corrupt(
                        start + 4,
                        "Control target exceeds instruction stream",
                    ));
                }
                Value::Group(vec![
                    operand(
                        if semantic_op == Some(79) {
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
                        if semantic_op == Some(79) {
                            ArgName::Metadata
                        } else {
                            ArgName::Target
                        },
                        Span {
                            offset: start as u64 + 4,
                            size: 4,
                        },
                        if semantic_op == Some(79) {
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
                if ty == 0 && matches!(semantic_op, Some(106 | 110)) {
                    expression::text_value(raw)
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
            if matches!(semantic_op, Some(43 | 44))
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
