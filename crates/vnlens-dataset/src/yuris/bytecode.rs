//! Foreground es.SND calls bind only to the immediately following message block.
//! RETURNCODE is the message boundary; WORD and constant _ interpolations are
//! concatenated. Jumps, calls and runtime expressions cannot borrow earlier voices.

use super::{
    Config, Dialogue,
    expression::{argument, call, integer, string},
    text,
};
use crate::resources::check;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicBool;
use vnlens_core::Result;
use vnlens_script::ir::{ArgName, Script, Value};

pub(super) fn collect(
    script: &Script,
    name: &str,
    config: &Config,
    cancel: &AtomicBool,
    output: &mut Vec<Dialogue>,
    skipped: &mut usize,
) -> Result<()> {
    let instructions = &script.instructions;
    let mut entry_points = config.entry_points.get(name).cloned().unwrap_or_default();
    for instruction in instructions {
        check(cancel)?;
        for arg in &instruction.args {
            // A zero next-branch target is the native "no ELSE" sentinel.
            if arg.name == ArgName::NextBranchTarget
                && matches!(&arg.value,
                Value::Group(fields) if fields.iter().any(|field| matches!(field.value, Value::InstructionTarget(0))))
            {
                continue;
            }
            targets(&arg.value, name, &mut entry_points);
        }
    }
    let mut index = 0;
    while index < instructions.len() {
        check(cancel)?;
        let start = index;
        let mut voices = BTreeMap::new();
        let mut complete = true;
        // Consecutive channels can form a chorus. A single-voice record cannot
        // claim a combined speaker or attach one channel to the entire chorus.
        while let Some(instruction) = instructions.get(index) {
            check(cancel)?;
            let channel = argument(instruction, "PINT").and_then(integer);
            let channel = match (call(instruction).as_deref(), channel) {
                (Some("es.SND"), Some(channel)) if (21..=30).contains(&channel) => Some(channel),
                // Earlier es.VoiceSet stores foreground slots 1..10 for the
                // following WORD. The same slot replaces a previous setting.
                (Some("es.VoiceSet"), Some(channel)) if (1..=10).contains(&channel) => {
                    Some(channel + 20)
                }
                _ => None,
            };
            let Some(channel) = channel else {
                break;
            };
            if index > start && entry_points.contains(&instruction.id) {
                complete = false;
            }
            voices.insert(channel, argument(instruction, "PSTR2").and_then(string));
            index += 1;
        }
        let Some(instruction) = instructions.get(index) else {
            if !voices.is_empty() {
                *skipped += 1;
            }
            break;
        };
        if instruction.opcode.native_mnemonic.as_deref() != Some("WORD") {
            if !voices.is_empty() {
                *skipped += 1;
            }
            index += 1;
            continue;
        }
        let mut raw = String::new();
        let mut terminated = false;
        while let Some(instruction) = instructions.get(index) {
            check(cancel)?;
            if index > start && entry_points.contains(&instruction.id) {
                complete = false;
            }
            match instruction.opcode.native_mnemonic.as_deref() {
                Some("WORD" | "_") => {
                    let value = instruction.args.first().and_then(|a| match &a.value {
                        Value::Text(v) => Some(v.clone()),
                        value => string(value),
                    });
                    if let Some(value) = value {
                        raw.push_str(&value);
                    } else {
                        complete = false;
                    }
                }
                Some("RETURNCODE") => {
                    index += 1;
                    terminated = true;
                    break;
                }
                _ => break,
            }
            index += 1;
        }
        if complete
            && terminated
            && voices.len() == 1
            && let Some(Some(voice)) = voices.values().next()
            && !voice.trim().is_empty()
            && let Some((speaker, text)) = text::split(&raw, config)
        {
            output.push(Dialogue {
                speaker,
                voice: voice.clone(),
                text,
            });
        } else {
            *skipped += 1;
        }
    }
    Ok(())
}

fn targets(value: &Value, name: &str, entries: &mut BTreeSet<u64>) {
    match value {
        Value::InstructionTarget(target) => {
            entries.insert(*target);
            // IF/LOOP targets name their closing instruction; execution can
            // resume at the next instruction without running a preceding SND.
            if let Some(next) = target.checked_add(1) {
                entries.insert(next);
            }
        }
        Value::ResourceInstructionTarget {
            resource,
            instruction,
            ..
        } if crate::resources::normalized(resource) == name => {
            entries.insert(*instruction);
        }
        Value::Group(fields) => {
            for field in fields {
                targets(&field.value, name, entries);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
#[path = "../../tests/yuris/bytecode.rs"]
mod tests;
