//! Runtime ERIS scenario syntax verified against es_scenario_lexer.yst,
//! es_scenario_macro_サウンド系.yst and es_scenario_text.yst: comments, VO/VO1..10,
//! optional (ID:...) markers and inline message text. Pending voices are consumed
//! once and cleared by control commands, dialogue boundaries and unknown macros.

use super::{Config, Dialogue, text};
use crate::resources::check;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use vnlens_core::Result;

pub(super) fn collect(
    source: &str,
    config: &Config,
    cancel: &AtomicBool,
    output: &mut Vec<Dialogue>,
    skipped: &mut usize,
) -> Result<()> {
    let mut voices = BTreeMap::new();
    let mut comment = false;
    for line in source.lines() {
        check(cancel)?;
        let mut remaining = line.trim();
        loop {
            if comment {
                let Some((_, after)) = remaining.split_once("*/") else {
                    break;
                };
                remaining = after.trim_start();
                comment = false;
            }
            if remaining.is_empty() || remaining.starts_with("//") {
                break;
            }
            if let Some(after) = remaining.strip_prefix("/*") {
                comment = true;
                remaining = after;
                continue;
            }
            if let Some(after) = remaining.strip_prefix('\\') {
                let end = after
                    .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '_'))
                    .unwrap_or(after.len());
                let name = &after[..end];
                let mut after = after[end..].trim_start();
                let mut parameter = None;
                if after.starts_with('(') {
                    let Some((args, rest)) = parameters(after) else {
                        voices.clear();
                        break;
                    };
                    parameter = args.first().cloned();
                    after = rest.trim_start();
                }
                let channel = if matches!(name, "VO" | "VO1") {
                    Some(1)
                } else {
                    name.strip_prefix("VO")
                        .and_then(|v| v.parse::<u8>().ok())
                        .filter(|v| (2..=10).contains(v))
                };
                if let Some(channel) = channel {
                    if let Some(voice) = parameter.filter(|s| !s.trim().is_empty()) {
                        voices.insert(channel, voice);
                    } else {
                        voices.remove(&channel);
                    }
                } else {
                    voices.clear();
                }
                remaining = after;
                continue;
            }
            if remaining.starts_with('#') || remaining.starts_with('*') {
                voices.clear();
                break;
            }
            if let Some(after) = remaining.strip_prefix("(ID:") {
                let Some((id, after)) = after.split_once(')') else {
                    voices.clear();
                    break;
                };
                if !id.bytes().all(|b| b.is_ascii_digit()) {
                    voices.clear();
                    break;
                }
                remaining = after;
            }
            let raw = remaining
                .split_once("//")
                .map_or(remaining, |(text, _)| text);
            if voices.len() == 1
                && let Some(voice) = voices.values().next()
                && let Some((speaker, text)) = text::split(raw, config)
            {
                output.push(Dialogue {
                    speaker,
                    voice: voice.clone(),
                    text,
                });
            } else {
                *skipped += 1;
            }
            voices.clear();
            break;
        }
    }
    Ok(())
}

fn parameters(source: &str) -> Option<(Vec<String>, &str)> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote = false;
    let mut depth = 0usize;
    for (index, ch) in source.char_indices() {
        match ch {
            '"' => quote = !quote,
            '(' if !quote => {
                depth += 1;
                if depth > 1 {
                    current.push(ch);
                }
            }
            ')' if !quote => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    args.push(current.trim().to_owned());
                    return Some((args, &source[index + 1..]));
                }
                current.push(ch);
            }
            ',' if !quote && depth == 1 => {
                args.push(current.trim().to_owned());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    None
}

#[cfg(test)]
#[path = "../../tests/yuris/scenario.rs"]
mod tests;
