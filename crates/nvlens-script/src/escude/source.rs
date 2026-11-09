//! Minimal lexical view of companion pseudo-C. Comments and whitespace do not
//! affect fingerprints; quoted tokens and escapes remain exact. No source is
//! executed. Semantic mappings are enabled only for reviewed token streams.
use super::*;

pub(super) fn tokens(bytes: &[u8]) -> Result<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if bytes[i..].starts_with(b"//") {
            while i < bytes.len() && !matches!(bytes[i], b'\r' | b'\n') {
                i += 1;
            }
            continue;
        }
        if bytes[i..].starts_with(b"/*") {
            let end = bytes[i + 2..]
                .windows(2)
                .position(|w| w == b"*/")
                .ok_or_else(|| bad(i, "Unterminated pseudo-C comment"))?;
            i += end + 4;
            continue;
        }
        let start = i;
        let first = bytes[i];
        i += 1;
        if matches!(first, b'\'' | b'"') {
            loop {
                let ch = *bytes
                    .get(i)
                    .ok_or_else(|| bad(start, "Unterminated pseudo-C string"))?;
                i += 1;
                if ch == first {
                    break;
                }
                if ch == b'\\' {
                    if i == bytes.len() {
                        return Err(bad(start, "Truncated pseudo-C escape"));
                    }
                    i += 1;
                }
            }
        } else if first.is_ascii_alphanumeric() || first == b'_' || first >= 128 {
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] >= 128)
            {
                i += 1;
            }
        }
        out.push(&bytes[start..i]);
    }
    Ok(out)
}

pub(super) fn fingerprint(tokens: &[&[u8]]) -> [u8; 16] {
    let parts: Vec<&[u8]> = tokens
        .iter()
        .flat_map(|token| [*token, b"\0".as_slice()])
        .collect();
    nvlens_crypto::hash::md5::digest_parts(&parts)
}

pub(super) fn registry(tokens: &[&[u8]]) -> Option<Vec<String>> {
    let starts: Vec<_> = tokens
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == [b"adv_proc_count".as_slice(), b"=", b"0", b";"])
        .map(|(i, _)| i + 4)
        .collect();
    let &[mut i] = starts.as_slice() else {
        return None;
    };
    let mut names = Vec::new();
    while tokens.get(i) == Some(&b"set_proc".as_slice()) {
        let call = tokens.get(i..i + 5)?;
        if call[1] != b"(" || call[3] != b")" || call[4] != b";" {
            return None;
        }
        let name = std::str::from_utf8(call[2]).ok()?;
        if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return None;
        }
        names.push(name.to_owned());
        i += 5;
    }
    (!names.is_empty()).then_some(names)
}

#[cfg(test)]
#[path = "../../tests/escude/source.rs"]
mod tests;
