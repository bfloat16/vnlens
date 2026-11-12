//! Constant-only evaluation of the existing postfix IR. Runtime loads and
//! unknown operations never become invented strings or partial dialogue text.

use vnlens_script::ir::{Arg, ArgName, Instruction, Value};

pub(super) fn argument<'a>(instruction: &'a Instruction, name: &str) -> Option<&'a Value> {
    instruction
        .args
        .iter()
        .find(|a| a.native_name.as_deref() == Some(name))
        .map(|a| &a.value)
}

pub(super) fn field(args: &[Arg], name: ArgName) -> Option<&Value> {
    args.iter().find(|a| a.name == name).map(|a| &a.value)
}

pub(super) fn string(value: &Value) -> Option<String> {
    if let Value::Text(text) = value {
        return Some(text.clone());
    }
    let Value::Expression(tokens) = value else {
        return None;
    };
    let mut stack = Vec::new();
    for token in tokens {
        match token.opcode.code {
            code if code == u32::from(b'M') => {
                let Value::Text(text) = &token.args.first()?.value else {
                    return None;
                };
                stack.push(text.clone());
            }
            code if code == u32::from(b'+') => {
                let right = stack.pop()?;
                stack.last_mut()?.push_str(&right);
            }
            _ => return None,
        }
    }
    if stack.len() == 1 { stack.pop() } else { None }
}

pub(super) fn integer(value: &Value) -> Option<i64> {
    match value {
        Value::Integer(n) => Some(*n),
        Value::Unsigned(n) => i64::try_from(*n).ok(),
        Value::Expression(tokens) => {
            let mut stack: Vec<i64> = Vec::new();
            for token in tokens {
                match u8::try_from(token.opcode.code).ok()? {
                    b'B' | b'W' | b'I' | b'L' => stack.push(integer(&token.args.first()?.value)?),
                    b'R' => {
                        let value = stack.last_mut()?;
                        *value = value.checked_neg()?;
                    }
                    _ => return None,
                }
            }
            if stack.len() == 1 { stack.pop() } else { None }
        }
        _ => None,
    }
}

pub(super) fn call(instruction: &Instruction) -> Option<String> {
    (instruction.opcode.native_mnemonic.as_deref() == Some("GOSUB"))
        .then(|| argument(instruction, "#").and_then(string))
        .flatten()
}
