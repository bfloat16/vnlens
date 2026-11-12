//! Foreground es.SND calls bind only to the immediately following message block.
//! RETURNCODE is the message boundary; WORD and constant _ interpolations are
//! concatenated. Jumps, calls and runtime expressions cannot borrow earlier voices.

use super::{
    Config, Dialogue,
    expression::{argument, call, integer, string},
    text,
};
use crate::resources::check;
use std::sync::atomic::AtomicBool;
use vnlens_core::Result;
use vnlens_script::ir::{Script, Value};

pub(super) fn collect(
    script: &Script,
    config: &Config,
    cancel: &AtomicBool,
    output: &mut Vec<Dialogue>,
    skipped: &mut usize,
) -> Result<()> {
    let instructions = &script.instructions;
    let mut index = 0;
    while index < instructions.len() {
        check(cancel)?;
        let mut voices = Vec::new();
        // Consecutive channels can form a chorus. A single-voice record cannot
        // claim a combined speaker or attach one channel to the entire chorus.
        while let Some(instruction) = instructions.get(index) {
            if call(instruction).as_deref() != Some("es.SND")
                || !argument(instruction, "PINT")
                    .and_then(integer)
                    .is_some_and(|n| (21..=30).contains(&n))
            {
                break;
            }
            voices.push(argument(instruction, "PSTR2").and_then(string));
            index += 1;
        }
        let Some(instruction) = instructions.get(index) else {
            break;
        };
        if instruction.opcode.native_mnemonic.as_deref() != Some("WORD") {
            index += 1;
            continue;
        }
        let mut raw = String::new();
        let mut complete = true;
        let mut terminated = false;
        while let Some(instruction) = instructions.get(index) {
            check(cancel)?;
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
            && let [Some(voice)] = voices.as_slice()
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
