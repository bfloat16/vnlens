//! Proven name hints: TJS constants and local CONST/CP/ADD expressions, textual
//! literals and literal concatenations, MDF/PSB references and the SCN list.
//! KAG sound references follow getExistSoundName/WaveSoundBuffer.open suffix
//! lookup and its .sli companion rule. No runtime code or numeric search runs.
use super::{bytecode, text};
use crate::ir::Value;
use nvlens_core::{Error, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicBool, Ordering},
};
fn check(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
/// Extracts exact strings and format-defined references without executing code.
/// Unknown binary formats return no candidates. Cancellation is checked between
/// instructions, strings and lines. Invalid recognized formats return errors.
pub fn name_candidates(data: &[u8], name: &str, cancel: &AtomicBool) -> Result<Vec<String>> {
    check(cancel)?;
    let unwrapped = crate::mdf::is_mdf(data)
        .then(|| crate::mdf::decode(data, None))
        .transpose()?;
    check(cancel)?;
    let data = unwrapped.as_deref().unwrap_or(data);
    if data.starts_with(b"TJS2100\0") {
        let mut out = bytecode::string_constants(data)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let script = bytecode::parse(data)?;
        let targets = script
            .instructions
            .iter()
            .flat_map(|i| i.args.iter())
            .filter_map(|o| {
                if let Value::CodeAddress(at) = o.value {
                    Some(at)
                } else {
                    None
                }
            })
            .collect::<BTreeSet<_>>();
        let mut registers = BTreeMap::<i64, String>::new();
        let mut object = None;
        for instruction in script.instructions {
            check(cancel)?;
            let current = instruction
                .attributes
                .iter()
                .find(|a| a.name == "object")
                .map(|a| a.value);
            if current != object || targets.contains(&instruction.span.offset) {
                registers.clear();
                object = current;
            }
            let args = &instruction.args;
            let reg = |i: usize| {
                args.get(i).and_then(|o| {
                    if let Value::Integer(v) = o.value {
                        Some(v)
                    } else {
                        None
                    }
                })
            };
            match instruction.opcode.code {
                1 => {
                    if let Some(dst) = reg(0) {
                        registers.remove(&dst);
                        if let Some(Value::Text(s)) = args.get(1).map(|o| &o.value) {
                            registers.insert(dst, s.clone());
                        }
                    }
                }
                2 => {
                    if let (Some(dst), Some(src)) = (reg(0), reg(1)) {
                        let value = registers.get(&src).cloned();
                        registers.remove(&dst);
                        if let Some(v) = value {
                            registers.insert(dst, v);
                        }
                    }
                }
                58 => {
                    if let (Some(dst), Some(src)) = (reg(0), reg(1)) {
                        let right = registers.get(&src).cloned();
                        let left = registers.remove(&dst);
                        if let (Some(mut left), Some(right)) = (left, right) {
                            left.push_str(&right);
                            out.insert(left.clone());
                            registers.insert(dst, left);
                        }
                    }
                }
                // Do not propagate through branches, calls or exception boundaries.
                15..=17 | 99..=102 | 119..=123 => registers.clear(),
                4 => registers.clear(),
                0 | 5..=10 | 14 | 104..=106 | 108..=109 | 111 | 113 | 118 | 125..=127 => {}
                _ => {
                    if let Some(dst) = reg(0) {
                        registers.remove(&dst);
                    }
                }
            }
        }
        return Ok(out.into_iter().collect());
    }
    if data.starts_with(b"PSB\0") {
        let psb = crate::psb::parse_source(&data, None)?;
        return psb_candidates(&psb, cancel);
    }
    let decoded = text::decode(data)?;
    let plain = if let Some(value) = decoded {
        value
    } else {
        let Ok(value) = std::str::from_utf8(data) else {
            return Ok(Vec::new());
        };
        if value
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        {
            return Ok(Vec::new());
        }
        value.to_owned()
    };
    let mut out = literals(&plain, cancel)?;
    if name
        .rsplit('/')
        .next()
        .is_some_and(|n| n.eq_ignore_ascii_case("sysse.ini"))
    {
        // SysSE definitions use tag=file[:channel]; @tag values are aliases.
        for line in plain.lines() {
            check(cancel)?;
            let line = line.trim();
            if line.starts_with(['#', ';']) {
                continue;
            }
            if let Some((_, value)) = line.split_once('=') {
                sound_candidates(value.split(':').next().unwrap_or("").trim(), &mut out);
            }
        }
    }
    // Unquoted KAG storage= references and text resource lists carry complete
    // tokens. Hash verification, not a guessed suffix, selects actual entries.
    for line in plain.lines() {
        check(cancel)?;
        if line.trim_start().starts_with([';', '#']) {
            continue;
        }
        for token in line.split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '=' | '"' | '\'' | '[' | ']' | '(' | ')' | ',' | ';' | '{' | '}'
                )
        }) {
            if !token.is_empty() {
                out.insert(token.into());
            }
        }
    }
    if name.rsplit('/').next() == Some("!scnlist.txt") {
        for line in plain.lines() {
            check(cancel)?;
            let line = line.trim();
            if line.starts_with(['#', '!']) || line.is_empty() || line.contains(':') {
                continue;
            }
            let storage = line
                .split('\t')
                .next()
                .unwrap_or("")
                .rsplit(['/', '\\', '>'])
                .next()
                .unwrap_or("");
            if storage.is_empty() || storage == "-" {
                continue;
            }
            for base in [
                format!("{storage}.scn"),
                format!("{}.scn", storage.strip_suffix(".txt").unwrap_or(storage)),
            ] {
                out.insert(base.clone());
                out.insert(format!("scenario/{base}"));
                out.insert(format!("scn/{base}"));
            }
        }
    }
    Ok(out.into_iter().collect())
}

fn psb_candidates(psb: &crate::psb::Psb, cancel: &AtomicBool) -> Result<Vec<String>> {
    use crate::psb::PsbValue;
    let mut out = psb
        .strings
        .iter()
        .chain(&psb.names)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut pending = vec![&psb.root];
    while let Some(value) = pending.pop() {
        check(cancel)?;
        match value {
            PsbValue::Object(fields) => {
                if let Some(voice) = fields.get("voice").and_then(PsbValue::as_str) {
                    sound_candidates(voice, &mut out);
                }
                if fields
                    .get("tagname")
                    .and_then(PsbValue::as_str)
                    .is_some_and(|tag| matches!(tag, "voice" | "bgm" | "se" | "playse" | "sound"))
                {
                    for field in ["file", "storage"] {
                        if let Some(sound) = fields.get(field).and_then(PsbValue::as_str) {
                            sound_candidates(sound, &mut out);
                        }
                    }
                }
                pending.extend(fields.values());
            }
            PsbValue::List(values) => pending.extend(values),
            _ => {}
        }
    }
    Ok(out.into_iter().collect())
}

fn sound_candidates(value: &str, out: &mut BTreeSet<String>) {
    let value = value.trim();
    if value.is_empty() || value.starts_with(['@', '&', '%', '*']) || value.contains("${") {
        return;
    }
    // The KAG sound reference's optional *label selects a playback position.
    let storage = value.split('*').next().unwrap_or(value);
    out.insert(storage.into());
    let leaf = storage.rsplit(['/', '\\']).next().unwrap_or(storage);
    if leaf.contains('.') {
        if !leaf.ends_with(".sli") {
            out.insert(format!("{storage}.sli"));
        }
    } else {
        // KAG getExistSoundName tries these audio extensions; native
        // tTJSNI_WaveSoundBuffer::Open (sub_471200) appends .sli to the selected
        // path. Every resulting name still needs the archive's exact hash proof.
        for suffix in [".ogg", ".opus", ".wav", ".tcw"] {
            let filename = format!("{storage}{suffix}");
            out.insert(format!("{filename}.sli"));
            out.insert(filename);
        }
    }
}
fn literals(text: &str, cancel: &AtomicBool) -> Result<BTreeSet<String>> {
    let mut chars = text.chars().peekable();
    let mut out = BTreeSet::new();
    let mut previous = None::<String>;
    let mut concatenate = false;
    while let Some(c) = chars.next() {
        check(cancel)?;
        if c.is_whitespace() {
            continue;
        }
        if c == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for c in chars.by_ref() {
                if c == '\n' {
                    break;
                }
            }
            continue;
        }
        if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut star = false;
            for c in chars.by_ref() {
                if star && c == '/' {
                    break;
                }
                star = c == '*';
            }
            continue;
        }
        if c == '+' && previous.is_some() && !concatenate {
            concatenate = true;
            continue;
        }
        if matches!(c, '\'' | '"') {
            let quote = c;
            let mut value = String::new();
            let mut closed = false;
            let mut valid = true;
            while let Some(c) = chars.next() {
                if c == quote {
                    closed = true;
                    break;
                }
                if c != char::from(92) {
                    value.push(c);
                    continue;
                }
                let Some(escaped) = chars.next() else { break };
                match escaped {
                    '\\' | '\'' | '"' => value.push(escaped),
                    'n' => value.push('\n'),
                    'r' => value.push('\r'),
                    't' => value.push('\t'),
                    'x' | 'u' => {
                        let mut hex = String::new();
                        let count = if escaped == 'u' { 4 } else { 2 };
                        for _ in 0..count {
                            if let Some(c) = chars.next_if(|c| c.is_ascii_hexdigit()) {
                                hex.push(c)
                            } else {
                                break;
                            }
                        }
                        if hex.len() != count {
                            valid = false;
                        } else if let Ok(unit) = u32::from_str_radix(&hex, 16) {
                            if let Some(c) = char::from_u32(unit) {
                                value.push(c)
                            } else {
                                valid = false
                            }
                        }
                    }
                    _ => valid = false,
                }
            }
            if !closed || !valid {
                previous = None;
                concatenate = false;
                continue;
            }
            out.insert(value.clone());
            if concatenate && let Some(mut prefix) = previous.take() {
                prefix.push_str(&value);
                out.insert(prefix.clone());
                value = prefix;
            }
            previous = Some(value);
            concatenate = false;
        } else {
            previous = None;
            concatenate = false;
        }
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;

    fn scene_fixture() -> Vec<u8> {
        fn array(out: &mut Vec<u8>, values: &[u8]) {
            out.extend([0x0d, values.len() as u8, 0x0d]);
            out.extend(values);
        }
        let mut out = vec![0; 44];
        out[..4].copy_from_slice(b"PSB\0");
        BinaryWriter::u16_le(3, &mut out[4..]);
        BinaryWriter::u32_le(44, &mut out[8..]);
        let names = out.len();
        array(&mut out, &[0; 120]);
        let mut parents = [0; 120];
        parents[119] = b'e';
        parents[usize::from(b'e')] = b'c';
        parents[usize::from(b'c')] = b'i';
        parents[usize::from(b'i')] = b'o';
        parents[usize::from(b'o')] = b'v';
        array(&mut out, &parents);
        array(&mut out, &[119]);
        let strings = out.len();
        array(&mut out, &[0, 10]);
        let text = out.len();
        out.extend(b"scene_001\0unrelated\0");
        let offsets = out.len();
        array(&mut out, &[0]);
        let lengths = out.len();
        array(&mut out, &[1]);
        let entries = out.len();
        out.push(0x21);
        array(&mut out, &[0]);
        array(&mut out, &[0]);
        out.extend([0x15, 0]);
        let resource = out.len();
        out.push(0);
        for (at, value) in [
            (12, names),
            (16, strings),
            (20, text),
            (24, offsets),
            (28, lengths),
            (32, resource),
            (36, entries),
        ] {
            BinaryWriter::u32_le(value as u32, &mut out[at..]);
        }
        out
    }

    #[test]
    fn mdf_scenario_voice_fields_generate_sound_and_companion_names() -> Result<()> {
        let cancel = AtomicBool::new(false);
        let plain = scene_fixture();
        let mdf = crate::mdf::encode_fixture(&plain);
        let json = crate::decode_text_as("script/krkr", &plain)?.ok_or(Error::InvalidFormat)?;
        assert_eq!(
            crate::decode_text_as("script/krkr", &mdf)?,
            Some(json.clone())
        );
        let tree: serde_json::Value =
            serde_json::from_str(&json).map_err(|e| Error::Unsupported(e.to_string()))?;
        assert_eq!(tree["voice"], "scene_001");
        let raw = name_candidates(&plain, "scene.scn", &cancel)?;
        let wrapped = name_candidates(&mdf, "hashed", &cancel)?;
        assert_eq!(raw, wrapped);
        assert!(wrapped.contains(&"scene_001.opus".into()));
        assert!(wrapped.contains(&"scene_001.opus.sli".into()));
        assert!(!wrapped.contains(&"unrelated.opus".into()));
        assert!(!wrapped.contains(&"scene_002.opus".into()));
        let mut broken = mdf.clone();
        let end = broken.len() - 1;
        broken[end] ^= 1;
        assert!(name_candidates(&broken, "scene.scn", &cancel).is_err());
        assert!(matches!(
            name_candidates(&mdf, "scene.scn", &AtomicBool::new(true)),
            Err(Error::Cancelled)
        ));
        Ok(())
    }

    #[test]
    fn sysse_aliases_channels_and_explicit_extensions() -> Result<()> {
        let cancel = AtomicBool::new(false);
        let input=b"# skipped = phantom\nvoice.test = sys_011 : 9\nclick=@select\nend = music.opus*chorus\nexpression = &getVoice()\n";
        let names = name_candidates(input, "main/sysse.ini", &cancel)?;
        assert!(names.contains(&"sys_011.opus".into()));
        assert!(names.contains(&"music.opus.sli".into()));
        for name in [
            "select.opus",
            "phantom.opus",
            "music.opus.opus",
            "getVoice().opus",
        ] {
            assert!(!names.contains(&name.into()));
        }
        assert!(!name_candidates(input, "other.txt", &cancel)?.contains(&"sys_011.opus".into()));
        Ok(())
    }
    #[test]
    fn exact_text_concatenations_and_scene_rules_only() -> Result<()> {
        let cancel = AtomicBool::new(false);
        let names=name_candidates(br#"var a="scenario/" + "first.ks"; var b="bg"+unknown+"01"; @image storage=bg/room.png"#,"test.tjs",&cancel)?;
        assert!(names.contains(&"scenario/first.ks".into()));
        assert!(names.contains(&"bg/room.png".into()));
        assert!(!names.contains(&"bg01".into()));
        assert!(!names.contains(&"first.tjs".into()));
        let names = name_candidates(b"chapter01.txt\tlabel", "!scnlist.txt", &cancel)?;
        assert!(names.contains(&"scenario/chapter01.scn".into()));
        assert!(matches!(
            name_candidates(b"text", "x", &AtomicBool::new(true)),
            Err(Error::Cancelled)
        ));
        Ok(())
    }
}
