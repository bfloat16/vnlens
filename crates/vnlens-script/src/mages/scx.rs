//! SC3: LE header offsets, 4096-entry label table, bytecode, text offsets and
//! return offsets. Code traversal follows declared entries and decoded local
//! branches; external-script labels stay external. No byte-pattern resync.
use super::{Layout, arg, corrupt, opcode, section};
use crate::ir::*;
use std::collections::{BTreeMap, BTreeSet};
use vnlens_core::{Error, Result};
use vnlens_io::BinaryReader;

const CODE_START: usize = 12 + 4096 * 4;

pub(super) fn disassemble(data: &[u8], layout: Layout) -> Result<Script> {
    let mut r = BinaryReader::new(data);
    if r.read_bytes(4)? != b"SC3\0" {
        return Err(Error::InvalidFormat);
    }
    let code_end = r.read_u32_le()? as usize;
    let returns_start = r.read_u32_le()? as usize;
    if code_end < CODE_START
        || returns_start < code_end
        || returns_start > data.len()
        || !(returns_start - code_end).is_multiple_of(4)
    {
        return Err(corrupt(4, "Invalid SC3 table offsets"));
    }
    let labels = table(&data[12..CODE_START])?;
    let texts = table(&data[code_end..returns_start])?;
    let returns_end = returns_start + (data.len() - returns_start) / 4 * 4;
    let returns = table(&data[returns_start..returns_end])?;
    let mut pending = BTreeSet::new();
    let mut initial = labels.first().copied();
    let mut data_labels = BTreeSet::new();
    if let Some(&entry) = returns.first()
        && (CODE_START..code_end).contains(&(entry as usize))
    {
        pending.insert(entry as usize);
    }
    let mut instructions: BTreeMap<usize, Instruction> = BTreeMap::new();
    let mut unresolved = Vec::new();
    while let Some((mut at, candidate)) = pending.pop_first().map(|p| (p, false)).or_else(|| {
        initial
            .take()
            .map(|p| p as usize)
            .filter(|p| (CODE_START..code_end).contains(p) && !data_labels.contains(p))
            .map(|p| (p, true))
    }) {
        let block_start = at;
        while at < code_end && !instructions.contains_key(&at) {
            if (candidate || at != block_start) && data_labels.contains(&at) {
                break;
            }
            // A label can start an inline table after alignment bytes. Do not
            // consume that declared data as the tail of a bytecode instruction.
            if at != block_start && data_labels.range(at..).next().is_some_and(|&p| p - at < 2) {
                break;
            }
            if instructions
                .range(..at)
                .next_back()
                .is_some_and(|(_, i)| i.span.offset + i.span.size > at as u64)
            {
                return Err(corrupt(at, "SC3 branch enters an instruction operand"));
            }
            let decoded = opcode::read(&data[..code_end], at, layout);
            // Label zero is also the default address of a data-only macro
            // resource (e.g. a table read by another script). It is only a
            // candidate until a code reference establishes its type. Keep an
            // undecodable candidate in the raw section; confirmed code still
            // reports an unknown layout rather than guessing a new boundary.
            if candidate && at == block_start && matches!(decoded, Err(Error::Unsupported(_))) {
                break;
            }
            let decoded =
                decoded.map_err(
                    |error| match (error, instructions.range(..at).next_back()) {
                        (Error::Unsupported(reason), Some((offset, previous))) => {
                            Error::Unsupported(format!(
                                "{reason}; preceding SC3 instruction 0x{:04X} at 0x{offset:X}",
                                previous.opcode.code
                            ))
                        }
                        (error, _) => error,
                    },
                );
            let mut instruction = match decoded {
                Ok(instruction) => instruction,
                Err(error @ Error::Unsupported(_)) => {
                    // Other reachable blocks may establish a forward data
                    // label. Defer the error until that evidence is available.
                    unresolved.push((at, at == block_start && !candidate, error));
                    break;
                }
                Err(error) => return Err(error),
            };
            let end = usize::try_from(instruction.span.offset + instruction.span.size)
                .map_err(|_| corrupt(at, "SC3 instruction address exceeds host range"))?;
            if instructions.range(at..end).next().is_some() {
                return Err(corrupt(at, "Overlapping SC3 instructions"));
            }
            let code = instruction.opcode.code;
            let mut resolved = Vec::new();
            for a in &instruction.args {
                if let Value::Expression(tokens) = &a.value {
                    for pair in tokens.windows(2) {
                        if pair[0].opcode.code == 0x2b
                            && pair[1].opcode.code & 0x80 != 0
                            && let Some(Value::Integer(index)) =
                                pair[1].args.first().map(|a| &a.value)
                            && let Ok(index) = usize::try_from(*index)
                            && let Some(&address) = labels.get(index)
                        {
                            data_labels.insert(address as usize);
                        }
                    }
                }
                if a.name == ArgName::NextBranchTarget
                    && let Value::CodeAddress(target) = a.value
                {
                    let target = usize::try_from(target)
                        .map_err(|_| corrupt(at, "SC3 branch address exceeds host range"))?;
                    if (CODE_START..code_end).contains(&target) {
                        pending.insert(target);
                    }
                    continue;
                }
                let Value::Unsigned(index) = a.value else {
                    continue;
                };
                let (target, local) = match a.name {
                    ArgName::LabelId => (
                        labels.get(index as usize).copied(),
                        !matches!(code, 0x01 | 0x0c | 0x0d | 0x1b | 0x55 | 0x56),
                    ),
                    ArgName::LabelBase => (labels.get(index as usize).copied(), false),
                    ArgName::ReturnTargets => (returns.get(index as usize).copied(), true),
                    ArgName::StringIndex => (texts.get(index as usize).copied(), false),
                    _ => continue,
                };
                if let Some(target) = target {
                    if local && (CODE_START..code_end).contains(&(target as usize)) {
                        pending.insert(target as usize);
                        resolved.push(arg(
                            ArgName::ResolvedTarget,
                            a.span.offset as usize,
                            a.span.offset as usize,
                            Value::CodeAddress(u64::from(target)),
                        ));
                    } else if matches!(a.name, ArgName::StringIndex | ArgName::LabelBase)
                        && (target as usize) < data.len()
                    {
                        data_labels.insert(target as usize);
                        resolved.push(arg(
                            ArgName::DataOffset,
                            a.span.offset as usize,
                            a.span.offset as usize,
                            Value::DataAddress(u64::from(target)),
                        ));
                    }
                }
            }
            if code == 0x08 {
                // A statically selected case has an exact table element. Dynamic
                // selectors retain their expression and table label unchanged.
                if let [selector, label] = instruction.args.as_slice()
                    && let Value::Unsigned(index) = label.value
                    && let Some(&base) = labels.get(index as usize)
                    && let Some(index) = constant(&selector.value)
                    && let Ok(index) = usize::try_from(index)
                    && let Some(position) = index
                        .checked_mul(2)
                        .and_then(|n| n.checked_add(base as usize))
                    && position >= CODE_START
                    && position <= code_end.saturating_sub(2)
                {
                    let case = usize::from(BinaryReader::u16_le(&data[position..position + 2]));
                    if let Some(&target) = labels.get(case)
                        && (CODE_START..code_end).contains(&(target as usize))
                    {
                        pending.insert(target as usize);
                        resolved.push(arg(
                            ArgName::ResolvedTarget,
                            position,
                            position,
                            Value::CodeAddress(u64::from(target)),
                        ));
                    }
                }
            }
            let indirect_jump = code == 0x5a
                && instruction
                    .args
                    .first()
                    .is_some_and(|a| matches!(a.value, Value::Unsigned(1)));
            let legacy_jump = code == 0x50
                && layout.glyph_width == 2
                && instruction
                    .args
                    .first()
                    .is_some_and(|a| matches!(a.value, Value::Unsigned(0 | 3 | 6)));
            instruction.args.extend(resolved);
            instructions.insert(at, instruction);
            if indirect_jump
                || legacy_jump
                || matches!(
                    code,
                    0 | 6 | 7 | 8 | 0x0b | 0x0c | 0x0d | 0x0e | 0x1b | 0x34 | 0x48
                )
            {
                break;
            }
            at = end;
        }
    }
    for (at, code_target, error) in unresolved {
        if code_target || !data_labels.range(at..).next().is_some_and(|&p| p - at < 2) {
            return Err(error);
        }
    }
    Ok(Script {
        ir_version: VERSION,
        format: "scx/mages".into(),
        format_version: 3,
        sections: vec![
            section("header", data, 0, 12),
            section("labels", data, 12, CODE_START),
            section("code", data, CODE_START, code_end),
            section("text_offsets", data, code_end, returns_start),
            section("return_offsets_and_data", data, returns_start, data.len()),
        ],
        instructions: instructions.into_values().collect(),
    })
}

fn table(data: &[u8]) -> Result<Vec<u32>> {
    let mut r = BinaryReader::new(data);
    let mut values = Vec::new();
    while r.remaining() != 0 {
        values.push(r.read_u32_le()?);
    }
    Ok(values)
}
fn constant(value: &Value) -> Option<i64> {
    let Value::Expression(tokens) = value else {
        return None;
    };
    let [token, end] = tokens.as_slice() else {
        return None;
    };
    if token.opcode.code & 0x80 == 0 || end.opcode.code != 0 {
        return None;
    }
    token.args.iter().find_map(|a| {
        if let Value::Integer(v) = a.value {
            Some(v)
        } else {
            None
        }
    })
}
