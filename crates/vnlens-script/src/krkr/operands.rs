//! TJS register, property and call operands. Register indices are signed slots,
//! never byte addresses. Derived values and implicit VM state have empty spans.
use super::{bad, bytecode::operand};
use crate::ir::*;
use vnlens_core::Result;

pub(super) fn register(name: ArgName, at: usize, size: usize, index: i16) -> Arg {
    operand(
        name,
        at,
        size,
        Value::Group(vec![operand(
            ArgName::Register,
            at,
            size,
            Value::Integer(i64::from(index)),
        )]),
    )
}

fn flag(name: ArgName, at: usize, reference: bool) -> Arg {
    operand(
        name,
        at,
        0,
        Value::Expression(vec![Token {
            opcode: Opcode {
                operation: Operation::Storage(if reference {
                    StorageOperation::Reference
                } else {
                    StorageOperation::Load
                }),
                variant: Some(Qualifier::Flag),
                namespace: "krkr/tjs2".into(),
                code: 0,
                native_mnemonic: None,
            },
            span: Span {
                offset: at as u64,
                size: 0,
            },
            args: Vec::new(),
            raw: Vec::new(),
        }]),
    )
}

fn constant(name: ArgName, at: usize, index: i16, values: &[Value]) -> Result<Arg> {
    let value = usize::try_from(index)
        .ok()
        .and_then(|i| values.get(i))
        .ok_or_else(|| bad(at, "TJS local constant index out of range"))?;
    Ok(operand(
        name,
        at,
        2,
        Value::Group(vec![
            operand(
                ArgName::ConstantIndex,
                at,
                2,
                Value::Integer(i64::from(index)),
            ),
            operand(ArgName::Value, at, 0, value.clone()),
        ]),
    ))
}

fn property(name: ArgName, object: Arg, key: Option<Arg>, attributes: Vec<Attribute>) -> Arg {
    let at = object.span.offset;
    let mut size = object.span.size;
    let mut fields = vec![object];
    if let Some(key) = key {
        size += key.span.size;
        fields.push(key);
    }
    Arg {
        name,
        native_name: None,
        span: Span { offset: at, size },
        value: Value::Group(fields),
        attributes,
    }
}

pub(super) fn decode(
    words: &[i16],
    at: usize,
    pc: usize,
    code_base: usize,
    code_len: usize,
    values: &[Value],
) -> Result<Vec<Arg>> {
    let op = words[0];
    let reg = |name, i| register(name, at + i * 2, 2, words[i]);
    let number = |name, i| operand(name, at + i * 2, 2, Value::Integer(i64::from(words[i])));
    let con = |name, i| constant(name, at + i * 2, words[i], values);
    let prop = |name, object, key, direct| -> Result<Arg> {
        Ok(property(
            name,
            reg(ArgName::Source, object),
            Some(if direct {
                con(ArgName::Index, key)?
            } else {
                reg(ArgName::Index, key)
            }),
            Vec::new(),
        ))
    };
    let handle = |name, i| property(name, reg(ArgName::Source, i), None, Vec::new());
    let mut args = Vec::new();
    match op {
        0 | 119 | 121 | 127 => {}
        1 => args.extend([reg(ArgName::Destination, 1), con(ArgName::Source, 2)?]),
        2 => args.extend([reg(ArgName::Destination, 1), reg(ArgName::Source, 2)]),
        3 | 4 => {
            args.push(reg(ArgName::Destination, 1));
            if op == 4 {
                args.push(number(ArgName::Count, 2));
            }
            args.push(operand(ArgName::InitialValue, at, 0, Value::Nil));
        }
        5 | 6 => args.extend([
            flag(ArgName::Destination, at, true),
            reg(ArgName::Source, 1),
        ]),
        7..=10 => args.extend([
            reg(ArgName::Left, 1),
            reg(ArgName::Right, 2),
            flag(ArgName::Destination, at, true),
        ]),
        11 | 12 => args.extend([
            reg(ArgName::Destination, 1),
            flag(ArgName::Source, at, false),
        ]),
        14 => args.extend([
            flag(ArgName::Destination, at, true),
            flag(ArgName::Source, at, false),
        ]),
        15..=17 | 120 => {
            let target = pc
                .checked_add_signed(isize::from(words[1]))
                .filter(|&v| v < code_len)
                .ok_or_else(|| bad(at + 2, "TJS branch target out of range"))?;
            args.extend([
                number(ArgName::Delta, 1),
                operand(
                    ArgName::Target,
                    at + 2,
                    0,
                    Value::CodeAddress((code_base + target * 2) as u64),
                ),
            ]);
            if op == 120 {
                args.push(reg(ArgName::Destination, 2));
            } else if op != 17 {
                args.push(flag(ArgName::Condition, at, false));
            }
        }
        19..=21 | 23..=25 => {
            let mut source = if matches!(op, 21 | 25) {
                handle(ArgName::Source, 2)
            } else {
                prop(ArgName::Source, 2, 3, matches!(op, 19 | 23))?
            };
            source.attributes.push(Attribute {
                name: "write_back".into(),
                value: 1,
            });
            args.extend([reg(ArgName::Destination, 1), source]);
        }
        26..=81 => {
            args.push(reg(ArgName::Destination, 1));
            match (op - 26) % 4 {
                0 => args.push(reg(ArgName::Right, 2)),
                form => {
                    let mut left = if form == 3 {
                        handle(ArgName::Left, 2)
                    } else {
                        prop(ArgName::Left, 2, 3, form == 1)?
                    };
                    left.attributes.push(Attribute {
                        name: "write_back".into(),
                        value: 1,
                    });
                    args.extend([left, reg(ArgName::Right, if form == 3 { 3 } else { 4 })]);
                }
            }
        }
        84 | 85 | 103 | 107 | 110 | 112 | 116 | 117 => {
            let mut source = prop(ArgName::Source, 2, 3, matches!(op, 84 | 103 | 110 | 116))?;
            if matches!(op, 110 | 112) {
                source.attributes.push(Attribute {
                    name: "ignore_property".into(),
                    value: 1,
                });
            }
            args.extend([reg(ArgName::Destination, 1), source]);
        }
        88 => args.extend([reg(ArgName::Destination, 1), reg(ArgName::Right, 2)]),
        99..=102 => {
            args.push(reg(ArgName::Destination, 1));
            let start = if matches!(op, 99 | 102) {
                args.push(reg(ArgName::Callee, 2));
                4
            } else {
                args.push(prop(ArgName::Callee, 2, 3, op == 100)?);
                5
            };
            let count = words[start - 1];
            args.push(number(ArgName::ArgumentCount, start - 1));
            if count == -1 {
                args.push(operand(
                    ArgName::Arguments,
                    at,
                    0,
                    Value::Expression(vec![Token {
                        opcode: Opcode {
                            operation: Operation::Storage(StorageOperation::GetArguments),
                            variant: None,
                            namespace: "krkr/tjs2".into(),
                            code: 0,
                            native_mnemonic: None,
                        },
                        span: Span {
                            offset: at as u64,
                            size: 0,
                        },
                        args: Vec::new(),
                        raw: Vec::new(),
                    }]),
                ));
            } else {
                let mut parameters = Vec::new();
                let first = if count == -2 {
                    args.push(number(ArgName::Count, start));
                    for (i, pair) in words[start + 1..].as_chunks::<2>().0.iter().enumerate() {
                        let pos = start + 1 + i * 2;
                        let field = if pair[0] == 2 {
                            number(ArgName::Reserved, pos + 1)
                        } else if matches!(pair[0], 0 | 1) {
                            reg(ArgName::Source, pos + 1)
                        } else {
                            number(ArgName::Unknown(1), pos + 1)
                        };
                        parameters.push(operand(
                            ArgName::ValueAt(i as u64),
                            at + pos * 2,
                            4,
                            Value::Group(vec![number(ArgName::Type, pos), field]),
                        ));
                    }
                    start + 1
                } else {
                    for i in start..words.len() {
                        parameters.push(reg(ArgName::ValueAt((i - start) as u64), i));
                    }
                    start
                };
                args.push(operand(
                    ArgName::Arguments,
                    at + first * 2,
                    (words.len() - first) * 2,
                    Value::Group(parameters),
                ));
            }
        }
        104..=106 | 108 | 109 | 111 | 113 => {
            let mut destination = prop(ArgName::Destination, 1, 2, matches!(op, 104..=106 | 111))?;
            for (name, enabled) in [
                ("ensure_member", matches!(op, 105 | 106 | 109 | 111 | 113)),
                ("hidden_member", op == 106),
                ("ignore_property", matches!(op, 111 | 113)),
            ] {
                if enabled {
                    destination.attributes.push(Attribute {
                        name: name.into(),
                        value: 1,
                    });
                }
            }
            args.extend([destination, reg(ArgName::Source, 3)]);
        }
        114 => args.extend([handle(ArgName::Destination, 1), reg(ArgName::Source, 2)]),
        115 => args.extend([reg(ArgName::Destination, 1), handle(ArgName::Source, 2)]),
        118 | 122 => args.push(reg(ArgName::Source, 1)),
        123 => args.extend([reg(ArgName::Destination, 1), reg(ArgName::Source, 2)]),
        125 => args.extend([reg(ArgName::Source, 1), reg(ArgName::Name, 2)]),
        126 => args.push(register(ArgName::Source, at, 0, -1)),
        13 | 18 | 22 | 82 | 83 | 86 | 87 | 89..=98 | 124 => args.push(reg(
            if op == 87 {
                ArgName::Source
            } else {
                ArgName::Destination
            },
            1,
        )),
        _ => return Err(bad(at, "Unknown TJS operand layout")),
    }
    if words.get(1) == Some(&0)
        && (matches!(op, 19..=21 | 23..=25 | 99..=102 | 116 | 117)
            || (26..=81).contains(&op) && (op - 26) % 4 != 0)
        && let Some(destination) = args.first_mut()
    {
        destination.attributes.push(Attribute {
            name: "discard_result".into(),
            value: 1,
        });
    }
    Ok(args)
}
