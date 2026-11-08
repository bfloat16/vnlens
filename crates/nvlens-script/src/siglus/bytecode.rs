//! Native args follow sub_674B40 and sub_678EC0. Some engine functions
//! consume an extra text marker from the code stream; resolving their constant
//! call path is necessary for instruction framing, not high-level decompilation.
use super::opcode;
use super::{corrupt, operand, scene::Scene};
use crate::ir::*;
use nvlens_core::Result;
use nvlens_io::BinaryReader;
use std::collections::BTreeSet;

#[derive(Debug, Default)]
struct Stack {
    values: Vec<Option<u32>>,
    marks: Vec<usize>,
}
impl Stack {
    fn pop(&mut self) -> Option<u32> {
        self.values.pop().flatten()
    }
    fn group(&mut self) -> Vec<Option<u32>> {
        let start = self
            .marks
            .pop()
            .unwrap_or(self.values.len())
            .min(self.values.len());
        self.values.split_off(start)
    }
    fn consume(&mut self, kind: u32) {
        if matches!(kind, 10 | 30) {
            self.pop();
        } else if kind != 20 {
            self.group();
        }
    }
}

fn word(r: &mut BinaryReader<'_>, base: usize, args: &mut Vec<Arg>, name: ArgName) -> Result<u32> {
    let at = base + r.position();
    let value = r.read_u32_le()?;
    args.push(operand(name, at, at + 4, Value::Unsigned(u64::from(value))));
    Ok(value)
}

/// Nested argument descriptors are parsed iteratively: -1 introduces another
/// counted list. Preserve file order; the VM places these arguments in reverse.
fn arguments(
    r: &mut BinaryReader<'_>,
    base: usize,
    args: &mut Vec<Arg>,
    stack: &mut Stack,
) -> Result<()> {
    let count = word(r, base, args, ArgName::ArgumentCount)?;
    let mut pending = vec![count];
    let mut index = 0;
    while let Some(left) = pending.last_mut() {
        if *left == 0 {
            pending.pop();
            continue;
        }
        *left -= 1;
        let kind = word(r, base, args, ArgName::ArgumentType(index as u64))?;
        index += 1;
        if kind == u32::MAX {
            pending.push(word(r, base, args, ArgName::TupleCount(index as u64))?);
        } else {
            stack.consume(kind);
        }
    }
    Ok(())
}
// sub_54C470 forwards these root functions to the text window dispatcher
// sub_550270 (4,5,9,26,27,50..52), or reads the marker itself (76,77,127).
fn text_marker(path: &[Option<u32>]) -> bool {
    matches!(
        path.first(),
        Some(Some(
            12 | 18 | 19 | 0x4c | 0x4d | 0x5a | 0x5b | 0x64 | 0x65 | 0x66 | 0x7f
        ))
    )
}

pub(super) fn parse(data: &[u8]) -> Result<Script> {
    let mut scene = Scene::new(data)?;
    let base = scene.fields[1] as usize;
    let bytes = scene.slice(scene.fields[1], u64::from(scene.fields[2]))?;
    let mut r = BinaryReader::new(bytes);
    let mut stack = Stack::default();
    let mut line = None;
    let mut instructions = Vec::new();
    let mut boundaries = BTreeSet::new();
    let mut targets = Vec::new();
    while r.remaining() > 0 {
        let start = base + r.position();
        boundaries.insert(start as u64);
        let code = r.read_u8()?;
        let mut args = Vec::new();
        let mut attributes = Vec::new();
        let mut selector = 0;
        match code {
            0 | 0x16 => {}
            1 => {
                line = Some(word(&mut r, base, &mut args, ArgName::SourceLine)?);
            }
            2 => {
                let kind = word(&mut r, base, &mut args, ArgName::ValueType)?;
                selector = kind;
                if matches!(kind, 10 | 20) {
                    let at = base + r.position();
                    let value = r.read_u32_le()?;
                    if kind == 10 {
                        stack.values.push(Some(value));
                        args.push(operand(
                            ArgName::Value,
                            at,
                            at + 4,
                            Value::Integer(i64::from(value as i32)),
                        ));
                    } else {
                        args.push(operand(ArgName::Text, at, at + 4, scene.text(value)?));
                        attributes.push(Attribute {
                            name: "string_id".into(),
                            value: u64::from(value),
                        });
                    }
                }
            }
            3 | 4 => {
                let kind = word(&mut r, base, &mut args, ArgName::ValueType)?;
                if kind == 10 {
                    if code == 3 {
                        stack.pop();
                    } else {
                        stack.values.push(stack.values.last().copied().flatten());
                    }
                }
            }
            5 => {
                stack.group();
                stack.values.push(None);
            }
            6 => {
                let start = stack
                    .marks
                    .last()
                    .copied()
                    .unwrap_or(stack.values.len())
                    .min(stack.values.len());
                let values = stack.values[start..].to_vec();
                stack.marks.push(stack.values.len());
                stack.values.extend(values);
            }
            7 => {
                let kind = word(&mut r, base, &mut args, ArgName::ValueType)?;
                word(&mut r, base, &mut args, ArgName::VariableId)?;
                if matches!(kind, 11 | 21) {
                    stack.pop();
                }
            }
            8 => {
                stack.marks.push(stack.values.len());
            }
            9 => {
                stack.values.clear();
                stack.marks.clear();
            }
            0x10..=0x14 => {
                let id = word(&mut r, base, &mut args, ArgName::LabelId)?;
                let address = scene.target(id)?;
                targets.push(address);
                args.push(operand(
                    ArgName::Target,
                    start + 1,
                    start + 5,
                    Value::CodeAddress(address),
                ));
                if matches!(code, 0x11 | 0x12) {
                    stack.pop();
                }
                if matches!(code, 0x13 | 0x14) {
                    arguments(&mut r, base, &mut args, &mut stack)?;
                    if code == 0x13 {
                        stack.values.push(None);
                    }
                }
            }
            0x15 => {
                arguments(&mut r, base, &mut args, &mut stack)?;
            }
            0x20 => {
                word(&mut r, base, &mut args, ArgName::DestinationType)?;
                let kind = word(&mut r, base, &mut args, ArgName::ValueType)?;
                word(&mut r, base, &mut args, ArgName::Mode)?;
                stack.consume(kind);
                stack.group();
            }
            0x21 | 0x22 => {
                let left = word(&mut r, base, &mut args, ArgName::LeftType)?;
                let right = if code == 0x22 {
                    word(&mut r, base, &mut args, ArgName::RightType)?
                } else {
                    0
                };
                let at = base + r.position();
                let operator = r.read_u8()?;
                args.push(operand(
                    ArgName::Operator,
                    at,
                    at + 1,
                    Value::Unsigned(u64::from(operator)),
                ));
                selector = u32::from(operator);
                if right == 10 {
                    stack.pop();
                }
                if left == 10 {
                    stack.pop();
                }
                if left == 10 || (0x10..=0x21).contains(&operator) {
                    stack.values.push(None);
                }
            }
            0x30 => {
                word(&mut r, base, &mut args, ArgName::Overload)?;
                arguments(&mut r, base, &mut args, &mut stack)?;
                let path = stack.group();
                let named = word(&mut r, base, &mut args, ArgName::NamedArgumentCount)?;
                for index in 0..named {
                    word(
                        &mut r,
                        base,
                        &mut args,
                        ArgName::NamedArgument(index as u64),
                    )?;
                }
                let result = word(&mut r, base, &mut args, ArgName::ReturnType)?;
                if text_marker(&path) {
                    word(&mut r, base, &mut args, ArgName::TextId)?;
                }
                if result == 10 {
                    stack.values.push(None);
                }
                args.push(operand(
                    ArgName::Callee,
                    start,
                    start,
                    Value::Group(
                        path.iter()
                            .enumerate()
                            .map(|(i, v)| {
                                operand(
                                    ArgName::Component(i as u64),
                                    start,
                                    start,
                                    v.map_or_else(
                                        || Value::Bytes(Vec::new()),
                                        |v| Value::Integer(i64::from(v as i32)),
                                    ),
                                )
                            })
                            .collect(),
                    ),
                ));
            }
            0x31 => {
                word(&mut r, base, &mut args, ArgName::TextId)?;
            }
            0x32 => {}
            _ => {} // The native default consumes exactly the opcode byte.
        };
        let end = base + r.position();
        instructions.push(Instruction {
            id: instructions.len() as u64,
            span: Span {
                offset: start as u64,
                size: (end - start) as u64,
            },
            source_line: line,
            opcode: opcode::opcode(code, selector),
            args,
            attributes,
        });
    }
    boundaries.insert((base + bytes.len()) as u64);
    if targets.iter().any(|a| !boundaries.contains(a)) {
        return Err(corrupt(
            base,
            "Siglus branch target is not an instruction boundary",
        ));
    }
    Ok(Script {
        ir_version: VERSION,
        format: "SiglusEngine scene".into(),
        format_version: 0x84,
        sections: vec![Section {
            name: "scene".into(),
            span: Span {
                offset: 0,
                size: data.len() as u64,
            },
            raw: data.to_vec(),
        }],
        instructions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;
    fn word(data: &mut Vec<u8>, value: u32) {
        let at = data.len();
        data.resize(at + 4, 0);
        BinaryWriter::u32_le(value, &mut data[at..]);
    }
    fn scene(code: &[u8], labels: &[u32], text: &str) -> Vec<u8> {
        let mut data = vec![0; 132];
        BinaryWriter::u32_le(132, &mut data);
        BinaryWriter::u32_le(132, &mut data[4..]);
        BinaryWriter::u32_le(code.len() as u32, &mut data[8..]);
        data.extend(code);
        let index = data.len() as u32;
        word(&mut data, 0);
        word(&mut data, text.encode_utf16().count() as u32);
        let string = data.len() as u32;
        for unit in text.encode_utf16() {
            let at = data.len();
            data.resize(at + 2, 0);
            BinaryWriter::u16_le(unit, &mut data[at..]);
        }
        let label = data.len() as u32;
        for &value in labels {
            word(&mut data, value);
        }
        for (at, value) in [
            (12, index),
            (16, 1),
            (20, string),
            (24, 1),
            (28, label),
            (32, labels.len() as u32),
        ] {
            BinaryWriter::u32_le(value, &mut data[at..]);
        }
        data
    }
    #[test]
    fn native_call_text_marker_nested_types_and_typed_targets() -> Result<()> {
        let mut code = vec![8, 2];
        word(&mut code, 10);
        word(&mut code, 18);
        code.push(2);
        word(&mut code, 10);
        word(&mut code, 7);
        code.push(0x30);
        for value in [0, 1, u32::MAX, 1, 10, 0, 0, 42] {
            word(&mut code, value);
        }
        let text_at = code.len();
        code.push(2);
        word(&mut code, 20);
        word(&mut code, 0);
        code.push(0x31);
        word(&mut code, 42);
        code.push(0x10);
        word(&mut code, 0);
        let source = scene(&code, &[text_at as u32], "你好😀");
        let script = parse(&source)?;
        assert_eq!(script.instructions.len(), 7);
        let call = &script.instructions[3];
        assert_eq!(
            call.opcode.operation,
            Operation::Runtime(RuntimeOperation::EngineCall)
        );
        assert!(
            call.args
                .iter()
                .any(|o| o.name == ArgName::TextId && matches!(o.value, Value::Unsigned(42)))
        );
        assert!(
            script.instructions[4]
                .args
                .iter()
                .any(|o| matches!(&o.value,Value::Text(s) if s=="你好😀"))
        );
        assert!(
            script.instructions[6]
                .args
                .iter()
                .any(|o| matches!(o.value,Value::CodeAddress(a) if a==132+text_at as u64))
        );
        assert_eq!(script.sections[0].raw, source);
        let mut bad = source.clone();
        let labels = BinaryReader::u32_le(&bad[28..]) as usize;
        BinaryWriter::u32_le(text_at as u32 + 1, &mut bad[labels..]);
        assert!(parse(&bad).is_err());
        assert!(parse(&source[..source.len() - 1]).is_err());
        Ok(())
    }
    #[test]
    fn stack_ops_and_arithmetic_keep_shared_names() -> Result<()> {
        let mut code = Vec::new();
        for value in [u32::MAX, 2] {
            code.push(2);
            word(&mut code, 10);
            word(&mut code, value);
        }
        code.push(0x22);
        word(&mut code, 10);
        word(&mut code, 10);
        code.push(1);
        code.push(4);
        word(&mut code, 10);
        code.push(3);
        word(&mut code, 10);
        for operator in [0x35, 0x36] {
            code.push(0x22);
            word(&mut code, 10);
            word(&mut code, 10);
            code.push(operator);
        }
        code.push(0xfe);
        let script = parse(&scene(&code, &[], ""))?;
        assert_eq!(
            script.instructions[2].opcode.operation,
            Operation::Basic(BasicOperation::Add)
        );
        assert_eq!(
            script.instructions[3].opcode.operation,
            Operation::Storage(StorageOperation::Duplicate)
        );
        assert_eq!(
            script.instructions[4].opcode.operation,
            Operation::Storage(StorageOperation::Pop)
        );
        assert_eq!(
            script.instructions[5]
                .opcode
                .variant
                .map(crate::ir::Qualifier::name),
            Some("arithmetic")
        );
        assert_eq!(
            script.instructions[6]
                .opcode
                .variant
                .map(crate::ir::Qualifier::name),
            Some("logical")
        );
        assert_eq!(script.instructions[7].opcode.operation, Operation::Unknown);
        assert_eq!(script.instructions[7].span.size, 1);
        Ok(())
    }
}
