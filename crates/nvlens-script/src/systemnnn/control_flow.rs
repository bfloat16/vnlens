//! CScript::Execute at 0x45bd70: conditions skip the following record or
//! brace-delimited block. Else-if is evaluated only by a preceding failed
//! if; reaching it sequentially skips its body. Targets below are derived
//! annotations, not synthetic instructions or unconditional extra branches.
use super::spt::{arg, byte_offset, word};
use crate::ir::{Arg, ArgName as A, Instruction, Value};
use nvlens_core::{Error, Result};
use std::collections::BTreeSet;

fn corrupt(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

pub(super) fn resolve(data: &[u8], instructions: &mut [Instruction]) -> Result<()> {
    for index in 0..instructions.len() {
        let instruction = &instructions[index];
        if instruction.opcode.namespace == "systemnnn/66660006"
            && instruction.opcode.code == 0x22220006
        {
            let cases = choice_cases(data, instructions, index)?;
            if !cases.is_empty() {
                let at = instruction.span.offset as usize;
                instructions[index]
                    .args
                    .push(arg(A::Targets, at, 0, Value::Group(cases)));
            }
            continue;
        }
        if instruction.opcode.namespace != "systemnnn/66660002" {
            continue;
        }
        let code = instruction.opcode.code;
        if !matches!(code, 0x55560002..=0x55560004 | 0x55560008 | 0x55560011) {
            continue;
        }
        let next = instructions
            .get(index + 1)
            .ok_or_else(|| corrupt(instruction.span.offset, "SPT conditional body is missing"))?;
        let target =
            if next.opcode.namespace == "systemnnn/66660002" && next.opcode.code == 0xa000007b {
                let offset = usize::try_from(next.span.offset)
                    .map_err(|_| corrupt(next.span.offset, "SPT target exceeds address space"))?;
                let words = word(&data[offset..], 3)?;
                next.span
                    .offset
                    .checked_add(byte_offset(words)? as u64)
                    .ok_or_else(|| corrupt(next.span.offset, "SPT block end overflow"))?
            } else {
                next.span.offset + next.span.size
            };
        let name = if matches!(code, 0x55560004 | 0x55560008) {
            A::Target
        } else {
            A::NextBranchTarget
        };
        let at = instruction.span.offset as usize;
        instructions[index]
            .args
            .push(arg(name, at, 0, Value::CodeAddress(target)));
    }
    // Validate all explicit and derived targets, including structured args.
    for instruction in instructions.iter() {
        let mut pending: Vec<&Arg> = instruction.args.iter().collect();
        while let Some(arg) = pending.pop() {
            match &arg.value {
                Value::CodeAddress(target)
                    if *target != data.len() as u64
                        && instructions
                            .binary_search_by_key(target, |i| i.span.offset)
                            .is_err() =>
                {
                    return Err(corrupt(
                        arg.span.offset,
                        "SPT target is not a record boundary",
                    ));
                }
                Value::Group(args) => pending.extend(args),
                _ => {}
            }
        }
    }
    Ok(())
}

// CScript::FindCase 0x45d290 follows the body's declared block end; it
// never scans into a different case's body for matching values.
fn choice_cases(data: &[u8], instructions: &[Instruction], owner: usize) -> Result<Vec<Arg>> {
    let mut cursor = owner + 1;
    if instructions
        .get(cursor)
        .is_some_and(|i| i.opcode.code == 0xa000007b && i.opcode.namespace == "systemnnn/66660002")
    {
        cursor += 1;
    }
    let mut cases = Vec::new();
    let mut visited = BTreeSet::new();
    while let Some(case) = instructions.get(cursor) {
        if case.opcode.namespace != "systemnnn/66660002" || case.opcode.code != 0x55560008 {
            break;
        }
        if !visited.insert(cursor) {
            return Err(corrupt(case.span.offset, "Cyclic SPT case chain"));
        }
        let at = case.span.offset as usize;
        let value = word(&data[at..], 3)?;
        cases.push(arg(
            A::Case(cases.len() as u64),
            at,
            0,
            Value::Group(vec![
                arg(A::Value, at + 12, 4, Value::Unsigned(u64::from(value))),
                arg(
                    A::Target,
                    at,
                    0,
                    Value::CodeAddress(case.span.offset + case.span.size),
                ),
            ]),
        ));
        let Some(body) = instructions.get(cursor + 1) else {
            break;
        };
        let target =
            if body.opcode.namespace == "systemnnn/66660002" && body.opcode.code == 0xa000007b {
                body.span
                    .offset
                    .checked_add(byte_offset(word(&data[body.span.offset as usize..], 3)?)? as u64)
                    .ok_or_else(|| corrupt(body.span.offset, "SPT case block end overflow"))?
            } else {
                body.span.offset + body.span.size
            };
        if target == data.len() as u64 {
            break;
        }
        cursor = instructions
            .binary_search_by_key(&target, |i| i.span.offset)
            .map_err(|_| corrupt(body.span.offset, "SPT case target is not a record boundary"))?;
        if instructions[cursor].opcode.namespace == "systemnnn/66660002"
            && instructions[cursor].opcode.code == 0xa000007d
        {
            cursor += 1;
        }
    }
    Ok(cases)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;

    #[test]
    fn choices_resolve_only_case_headers_and_preserve_values_and_encoded_spans() -> Result<()> {
        let mut words = vec![0; 32];
        words[..3].copy_from_slice(&[32, 0x66660001, 0x55550001]);
        words.extend([7, 0x66660006, 0x22220006, 2, 0, 1, 7]);
        words.extend([4, 0x66660002, 0xa000007b, 28]);
        words.extend([4, 0x66660002, 0x55560008, 1]);
        words.extend([3, 0x66660002, 0x55560001]);
        words.extend([4, 0x66660002, 0x55560008, 2]);
        words.extend([4, 0x66660002, 0xa000007b, 10]);
        words.extend([3, 0x66660002, 0x55560001]);
        words.extend([3, 0x66660002, 0xa000007d]);
        words.extend([3, 0x66660002, 0xa000007d]);
        words.extend([3, 0x66660002, 0x55560006]);
        let table = words.len();
        words[6] = 2;
        words[7] = table as u32 + 4;
        words.extend([
            8,
            0x66660001,
            0x55550002,
            0x44440001,
            table as u32 + 6,
            table as u32 + 7,
            0,
            0,
        ]);
        let mut data = vec![0; words.len() * 4];
        for (&value, target) in words.iter().zip(data.as_chunks_mut::<4>().0) {
            BinaryWriter::u32_le(value, target);
        }
        data[48..58].copy_from_slice(b"SPTHEADER0");
        data[(table + 6) * 4] = b'a';
        data[(table + 7) * 4] = b'b';
        let script = super::super::spt::parse(&data, None)?;
        let targets = script.instructions[1]
            .args
            .iter()
            .find(|arg| arg.name == A::Targets)
            .ok_or(Error::InvalidFormat)?;
        let Value::Group(cases) = &targets.value else {
            return Err(Error::InvalidFormat);
        };
        assert_eq!(cases.len(), 2);
        for (index, target_index) in [(0, 4), (1, 6)] {
            let Value::Group(fields) = &cases[index].value else {
                return Err(Error::InvalidFormat);
            };
            assert!(matches!(fields[0].value,Value::Unsigned(value) if value==index as u64+1));
            assert!(
                matches!(fields[1].value,Value::CodeAddress(target) if target==script.instructions[target_index].span.offset)
            );
            assert_eq!(fields[0].span.size, 4);
            assert_eq!(fields[1].span.size, 0);
        }
        assert!(
            script.instructions[3]
                .args
                .iter()
                .any(|arg| arg.name == A::Value)
        );
        Ok(())
    }
}
