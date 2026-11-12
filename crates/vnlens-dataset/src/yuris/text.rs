//! Message envelopes used by es.CHAR.NAME.SEARCH/es_text.yst. Explicit 【...】
//! keys and configured name/quote pairs delimit speakers. Ruby annotations keep
//! their written base; punctuation and spaces in the spoken text stay intact.

use super::Config;

pub(super) fn split(raw: &str, config: &Config) -> Option<(String, String)> {
    let raw = raw.trim();
    let (speaker, body) = if let Some(rest) = raw.strip_prefix('【') {
        let (name, body) = rest.split_once('】')?;
        (name, body)
    } else {
        let (name, body) = config
            .names
            .iter()
            .filter_map(|name| {
                let body = raw.strip_prefix(name)?;
                config
                    .markers
                    .iter()
                    .any(|mark| body.starts_with(mark))
                    .then_some((name.as_str(), body))
            })
            .max_by_key(|(name, _)| name.len())?;
        (name, body)
    };
    let speaker = speaker.trim();
    if speaker.is_empty() {
        return None;
    }
    let body = body.trim();
    let mut text = String::new();
    let mut remaining = body;
    while let Some((before, after)) = remaining.split_once('≪') {
        text.push_str(before);
        let (ruby, after) = after.split_once('≫')?;
        let (base, _) = ruby.split_once('／')?;
        text.push_str(base);
        remaining = after;
    }
    text.push_str(remaining);
    // Known inline line break; unparsed commands must not leak into training text.
    let mut clean = String::new();
    let mut remaining = text.as_str();
    while let Some((before, after)) = remaining.split_once('\\') {
        clean.push_str(before);
        let after = after.strip_prefix('R')?;
        if after.starts_with(|ch: char| ch.is_ascii_alphanumeric() || ch == '_' || ch == '.') {
            return None;
        }
        clean.push('\n');
        remaining = after;
    }
    clean.push_str(remaining);
    if clean.trim().is_empty() {
        return None;
    }
    Some((speaker.to_owned(), clean))
}

pub(super) fn identity(name: &str) -> bool {
    !name.trim().is_empty() && !name.contains(['?', '？', '＠', '／', '＆', '&'])
}

#[cfg(test)]
#[path = "../../tests/yuris/text.rs"]
mod tests;
