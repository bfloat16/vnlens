//! Native Lua disassembly in the shared document envelope, without semantic
//! opcode mapping. Mnemonics and args follow each standard Lua version.
//! Original chunk bytes, constants, IEEE bits and instruction offsets survive.
use super::{
    chunk::{Constant, Function},
    decode,
    instruction::Role,
    opcode::{Field, Kind, native_field},
    read,
};
use crate::ir::DataOperation;
use crate::ir::{
    self, Arg, Attribute, Instruction, Opcode, Operation, Script, Section, Span, Value,
};
use crate::ir::{ArgName, Qualifier};
use nvlens_core::{Error, Result};

pub(super) fn parse(data: &[u8]) -> Result<Script> {
    let chunk = read::read(data)?;
    let header = &chunk.header;
    let version = header.version;
    let width = usize::from(header.instruction_size);
    let opcode_mask = decode::mask(decode::layout(header).opcode);
    let rk_offset = if version == 0x50 { 250 } else { 256 };
    let mut instructions = Vec::new();
    for (function_id, raw) in chunk.functions.iter().enumerate() {
        let range = &raw.code_range;
        let mut path = Vec::new();
        let mut parent = raw.parent;
        while let Some((id, ordinal)) = parent {
            path.push(ordinal);
            parent = chunk.functions[id].parent;
        }
        path.reverse();
        let span = Span {
            offset: range.start as u64,
            size: 0,
        };
        let constants = raw
            .constants
            .iter()
            .enumerate()
            .map(|(i, c)| field(ArgName::Constant(i as u64), literal(c), span))
            .collect();
        instructions.push(Instruction {
            id: instructions.len() as u64,
            span,
            source_line: Some(raw.line_defined),
            opcode: Opcode {
                operation: Operation::Data(DataOperation::Record),
                variant: Some(Qualifier::Function),
                namespace: "lua.function".into(),
                code: 0,
                native_mnemonic: Some("function".into()),
            },
            args: vec![
                field(
                    ArgName::Path,
                    Value::Text(format!(
                        "main{}",
                        path.iter().map(|i| format!("/f{i}")).collect::<String>()
                    )),
                    span,
                ),
                field(
                    ArgName::SourceFile,
                    raw.source
                        .as_ref()
                        .map_or_else(|| Value::Bytes(Vec::new()), |s| text(s)),
                    span,
                ),
                field(ArgName::Constants, Value::Group(constants), span),
            ],
            attributes: vec![
                attr("function", function_id as u64),
                attr("parameters", u64::from(raw.num_params)),
                attr("registers", u64::from(raw.max_stack_size)),
                attr("vararg", u64::from(raw.vararg_flags)),
                attr("upvalues", u64::from(raw.num_upvalues)),
            ],
        });
        let decoded = decode::instructions(&chunk, raw)?;
        let mut owner_pc = 0;
        for instruction in &decoded {
            if instruction.role == Role::Code {
                owner_pc = instruction.pc;
            }
            let at = range.start + instruction.pc as usize * width;
            if at.checked_add(width).is_none_or(|end| end > range.end) {
                return Err(Error::InvalidFormat);
            }
            let span = Span {
                offset: at as u64,
                size: width as u64,
            };
            let mut args = Vec::new();
            if let Some(op) = instruction.opcode {
                for (operand_id, &(f, kind)) in op.args().iter().enumerate() {
                    let v = i64::from(instruction.field(f));
                    let constant = match kind {
                        Kind::Constant => Some(v),
                        Kind::Rk if v >= i64::from(rk_offset) => Some(v - i64::from(rk_offset)),
                        Kind::Rk54 if instruction.field(Field::K) != 0 => Some(v),
                        _ => None,
                    };
                    let value = if let Some(index) = constant {
                        let c = usize::try_from(index)
                            .ok()
                            .and_then(|i| raw.constants.get(i))
                            .ok_or_else(|| Error::Corrupt {
                                offset: at as u64,
                                reason: "Lua constant index is out of range".into(),
                            })?;
                        Value::Group(vec![
                            field(ArgName::ConstantIndex, Value::Integer(index), span),
                            field(ArgName::Value, literal(c), Span { size: 0, ..span }),
                        ])
                    } else {
                        match kind {
                            Kind::Register | Kind::Rk | Kind::Rk54 => {
                                reference(ArgName::Register, v, span)
                            }
                            Kind::Upvalue => reference(ArgName::Upvalue, v, span),
                            Kind::Function => reference(ArgName::FunctionIndex, v, span),
                            Kind::Signed => Value::Integer(v - 127),
                            _ => Value::Integer(v),
                        }
                    };
                    let name = native_field(f, kind);
                    let mut operand = field(ArgName::Native(name), value, span);
                    operand.native_name = Some(name.name().into());
                    operand
                        .attributes
                        .push(attr("operand_id", operand_id as u64));
                    args.push(operand);
                }
            }
            if instruction.role == Role::Code
                && let Some(target) = instruction.jump_target()
            {
                let address = i128::from(target) * width as i128 + range.start as i128;
                if address < range.start as i128 || address > range.end as i128 {
                    return Err(super::corrupt(at, "Lua jump is outside its function"));
                }
                // luac-style destination annotation; the encoded sBx/Bx/sJ
                // operand above remains a native integer field.
                args.push(field(
                    ArgName::Target,
                    Value::CodeAddress(address as u64),
                    Span { size: 0, ..span },
                ));
            }
            let name = instruction
                .opcode
                .map(|op| op.name().to_ascii_uppercase())
                .or_else(|| (instruction.role == Role::ExtraWord).then(|| ".word".into()));
            if instruction.opcode.is_none() {
                args.push(field(
                    ArgName::Word,
                    Value::Unsigned(u64::from(instruction.raw)),
                    span,
                ));
            }
            instructions.push(Instruction {
                id: instructions.len() as u64,
                span,
                source_line: line(raw, instruction.pc, version),
                opcode: Opcode {
                    operation: Operation::Native,
                    variant: None,
                    namespace: if instruction.role == Role::ExtraWord
                        && instruction.opcode.is_none()
                    {
                        format!("lua.{version:02x}.auxiliary")
                    } else {
                        format!("lua.{version:02x}")
                    },
                    code: if instruction.role == Role::ExtraWord && instruction.opcode.is_none() {
                        0
                    } else {
                        instruction.raw & opcode_mask
                    },
                    native_mnemonic: name,
                },
                args,
                attributes: {
                    let mut attributes = vec![
                        attr("function", function_id as u64),
                        attr("pc", u64::from(instruction.pc)),
                        attr("raw_word", u64::from(instruction.raw)),
                    ];
                    if instruction.role != Role::Code {
                        attributes.push(attr("owner_pc", u64::from(owner_pc)));
                    }
                    attributes
                },
            });
        }
    }
    Ok(Script {
        ir_version: ir::VERSION,
        format: "Lua".into(),
        format_version: u32::from(version),
        sections: vec![Section {
            name: "chunk".into(),
            span: Span {
                offset: 0,
                size: data.len() as u64,
            },
            raw: data.to_vec(),
        }],
        instructions,
    })
}
fn line(raw: &Function<'_>, pc: u32, version: u8) -> Option<u32> {
    if version < 0x54 {
        return raw.line_info.get(pc as usize).copied();
    }
    if raw.line_info.is_empty() {
        return None;
    }
    let anchor = raw.absolute_lines.iter().rev().find(|a| a.0 <= pc);
    let (mut line, start) = anchor.map_or((i64::from(raw.line_defined), 0), |a| {
        (i64::from(a.1), a.0 + 1)
    });
    for i in start..=pc {
        line += i64::from(*raw.line_info.get(i as usize)? as i8);
    }
    u32::try_from(line).ok()
}
fn text(bytes: &[u8]) -> Value {
    std::str::from_utf8(bytes)
        .map_or_else(|_| Value::Bytes(bytes.to_vec()), |s| Value::Text(s.into()))
}
fn literal(value: &Constant<'_>) -> Value {
    match value {
        Constant::Nil => Value::Nil,
        Constant::Boolean(v) => Value::Boolean(*v),
        Constant::Integer(v) => Value::Integer(*v),
        Constant::Float32(v) => Value::Float32Bits(*v),
        Constant::Float64(v) => Value::Float64Bits(*v),
        Constant::String(Some(s)) => text(s),
        Constant::String(None) => Value::Bytes(Vec::new()),
    }
}
fn reference(name: ArgName, index: i64, span: Span) -> Value {
    Value::Group(vec![field(name, Value::Integer(index), span)])
}
fn field(name: ArgName, value: Value, span: Span) -> Arg {
    Arg {
        name,
        native_name: None,
        span,
        value,
        attributes: Vec::new(),
    }
}
fn attr(name: &str, value: u64) -> Attribute {
    Attribute {
        name: name.into(),
        value,
    }
}
