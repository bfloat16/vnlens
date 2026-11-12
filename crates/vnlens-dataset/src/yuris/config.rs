//! Project definitions reached through YSLB, not hard-coded YSTB filenames.
//! ES.FOLDER.DEFINE assigns the ERIS folder matrix at [38,13] for foreground
//! voices. es.VO.PATHDEF records four case-insensitive prefixes and a folder;
//! es.VO.PATH.SEARCH takes the first matching definition (es_soundvo.yst).
//! Character keys are identities; replacement display strings are not used.

use super::expression::{argument, call, field, integer, string};
use crate::resources::check;
use crate::resources::{Resources, normalized};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicBool;
use vnlens_core::{Error, ResourceResolver, Result};
use vnlens_script::ir::{ArgName, Instruction, Script, Value};

#[derive(Debug)]
struct VoiceRule {
    prefix: String,
    folder: String,
    character: i64,
}

#[derive(Debug, Default)]
pub(crate) struct Config {
    pub(super) names: BTreeSet<String>,
    pub(super) markers: BTreeSet<String>,
    voice_root: String,
    voice_rules: Vec<VoiceRule>,
    other_folder: String,
}

impl Config {
    pub fn load(resources: &Resources, cancel: &AtomicBool) -> Result<Self> {
        let labels = script(resources, "ysbin/ysl.ybn")?;
        let mut config = Self::default();
        let folders = definition(resources, &labels, "ES.FOLDER.DEFINE", cancel)?;
        let mut root = None;
        for instruction in &folders {
            check(cancel)?;
            if instruction.opcode.native_mnemonic.as_deref() != Some("LET") {
                continue;
            }
            let Some(Value::Expression(tokens)) = field(&instruction.args, ArgName::Destination)
            else {
                continue;
            };
            let [variable, row, separator, column, end] = tokens.as_slice() else {
                continue;
            };
            if variable.opcode.code == u32::from(b'V')
                && separator.opcode.code == u32::from(b',')
                && end.opcode.code == u32::from(b')')
                && row.args.first().and_then(|a| integer(&a.value)) == Some(38)
                && column.args.first().and_then(|a| integer(&a.value)) == Some(13)
                && let Some(value) = field(&instruction.args, ArgName::Value).and_then(string)
            {
                if root.as_ref().is_some_and(|previous| previous != &value) {
                    return Err(Error::Unsupported(
                        "Conflicting ERIS voice folder definitions".into(),
                    ));
                }
                root = Some(value);
            }
        }
        config.voice_root =
            root.ok_or_else(|| Error::Unsupported("Missing ERIS voice folder definition".into()))?;
        for instruction in definition(resources, &labels, "ES.CHARNAME.DEFINE", cancel)? {
            check(cancel)?;
            match call(&instruction).as_deref() {
                Some("es.CHAR.NAME") => {
                    if let Some(name) = argument(&instruction, "PSTR").and_then(string) {
                        config.names.insert(name);
                    }
                }
                Some("es.CHAR.NAME.MARK.SET") => {
                    if let Some(mark) = argument(&instruction, "PSTR")
                        .and_then(string)
                        .filter(|v| !v.is_empty())
                    {
                        config.markers.insert(mark);
                    }
                }
                _ => {}
            }
        }
        let mut prefixes = Vec::new();
        let mut folder = String::new();
        for instruction in definition(resources, &labels, "ES.VOICE.DEFINE", cancel)? {
            check(cancel)?;
            match call(&instruction).as_deref() {
                Some("es.VO.PATH.STR.SET") => {
                    prefixes.clear();
                    for name in ["PSTR", "PSTR2", "PSTR3", "PSTR4"] {
                        if let Some(value) = argument(&instruction, name)
                            .and_then(string)
                            .filter(|v| !v.is_empty())
                        {
                            prefixes.push(normalized(&value));
                        }
                    }
                }
                Some("es.VO.PATH.FOLDER.SET") => {
                    folder = argument(&instruction, "PSTR")
                        .and_then(string)
                        .ok_or_else(|| Error::Unsupported("Dynamic ERIS voice folder".into()))?;
                }
                Some("es.VO.PATHDEF") => {
                    let character = argument(&instruction, "PINT")
                        .and_then(integer)
                        .ok_or_else(|| Error::Unsupported("Dynamic ERIS voice character".into()))?;
                    for prefix in prefixes.drain(..) {
                        config.voice_rules.push(VoiceRule {
                            prefix,
                            folder: folder.clone(),
                            character,
                        });
                    }
                    folder.clear();
                }
                Some("es.VO.OTHER.PATH.FOLDER.SET") => {
                    config.other_folder = argument(&instruction, "PSTR")
                        .and_then(string)
                        .ok_or_else(|| {
                            Error::Unsupported("Dynamic ERIS default voice folder".into())
                        })?;
                }
                _ => {}
            }
        }
        Ok(config)
    }

    /// A voice group can contain several characters. Resolve only identity
    /// components explicitly present in the speaker key and backed by another
    /// message or character definition. A bare unknown name remains unknown.
    pub fn speakers(
        &self,
        dialogues: &[super::Dialogue],
        cancel: &AtomicBool,
    ) -> Result<Vec<Option<String>>> {
        let group = |reference: &str| {
            let reference = normalized(reference);
            self.voice_rules
                .iter()
                .find(|rule| reference.starts_with(&rule.prefix))
                .map(|r| r.character)
        };
        let mut identities: BTreeMap<i64, BTreeSet<&str>> = BTreeMap::new();
        let mut known = BTreeSet::new();
        for name in &self.names {
            check(cancel)?;
            let name = name
                .strip_prefix('【')
                .and_then(|s| s.strip_suffix('】'))
                .unwrap_or(name);
            if super::text::identity(name) {
                known.insert(name);
            }
        }
        for dialogue in dialogues {
            check(cancel)?;
            if super::text::identity(&dialogue.speaker) {
                known.insert(dialogue.speaker.as_str());
                if let Some(id) = group(&dialogue.voice) {
                    identities.entry(id).or_default().insert(&dialogue.speaker);
                }
            }
        }
        let mut result = Vec::with_capacity(dialogues.len());
        for speaker in dialogues.iter().map(|dialogue| {
            if dialogue.speaker.contains(['＆', '&']) {
                return None;
            }
            if super::text::identity(&dialogue.speaker) {
                return Some(dialogue.speaker.clone());
            }
            if let Some(names) = group(&dialogue.voice).and_then(|id| identities.get(&id)) {
                let candidates = dialogue
                    .speaker
                    .split(['＠', '／'])
                    .map(str::trim)
                    .filter(|part| names.contains(part))
                    .collect::<BTreeSet<_>>();
                if candidates.len() == 1 {
                    return candidates.first().map(|s| (*s).to_owned());
                }
            }
            let candidates = dialogue
                .speaker
                .split(['＠', '／'])
                .map(str::trim)
                .filter(|part| known.contains(part))
                .collect::<BTreeSet<_>>();
            if candidates.len() == 1 {
                return candidates.first().map(|s| (*s).to_owned());
            }
            None
        }) {
            check(cancel)?;
            result.push(speaker);
        }
        Ok(result)
    }

    pub fn voice_path(&self, reference: &str) -> Option<String> {
        let reference = normalized(reference);
        let folder = self
            .voice_rules
            .iter()
            .find(|rule| reference.starts_with(&rule.prefix))
            .map_or(self.other_folder.as_str(), |rule| rule.folder.as_str());
        let path = format!("{}{folder}{reference}", self.voice_root);
        let mut parts = Vec::new();
        let path = normalized(&path);
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop()?;
                }
                _ => parts.push(part),
            }
        }
        (!parts.is_empty()).then(|| parts.join("/"))
    }
}

fn script(resources: &Resources, name: &str) -> Result<Script> {
    let bytes = resources
        .read_resource(name)?
        .ok_or_else(|| Error::Unsupported(format!("Missing YU-RIS companion: {name}")))?;
    vnlens_script::disassemble_as("ybn/yuris", &bytes, Some(resources))?
        .ok_or_else(|| Error::Unsupported(format!("Not a YU-RIS script: {name}")))
}

fn definition(
    resources: &Resources,
    labels: &Script,
    name: &str,
    cancel: &AtomicBool,
) -> Result<Vec<Instruction>> {
    let mut targets = labels.instructions.iter().filter(|instruction| {
        field(&instruction.args, ArgName::Name)
            .and_then(string)
            .as_deref()
            == Some(name)
    });
    let target = targets
        .next()
        .ok_or_else(|| Error::Unsupported(format!("Missing ERIS definition: {name}")))?;
    if targets.next().is_some() {
        return Err(Error::Unsupported(format!(
            "Ambiguous ERIS definition: {name}"
        )));
    }
    let id = field(&target.args, ArgName::ScriptId)
        .and_then(integer)
        .ok_or(Error::InvalidFormat)?;
    let start = field(&target.args, ArgName::Instruction)
        .and_then(integer)
        .ok_or(Error::InvalidFormat)?;
    let script = script(resources, &format!("ysbin/yst{id:05}.ybn"))?;
    let start = usize::try_from(start).map_err(|_| Error::InvalidFormat)?;
    if start > script.instructions.len() {
        return Err(Error::InvalidFormat);
    }
    let instructions = script.instructions.into_iter().skip(start);
    // Some projects initialize unrelated counters in loops after the voice
    // declarations. Those do not change the mapping; conditional definitions
    // themselves cannot be flattened without knowing the runtime state.
    let mut result = Vec::new();
    let mut depth = 0usize;
    for instruction in instructions {
        check(cancel)?;
        match instruction.opcode.native_mnemonic.as_deref() {
            Some("RETURN" | "END") if depth == 0 => break,
            Some("GO" | "RETURN" | "END") => {
                return Err(Error::Unsupported(format!(
                    "Dynamic ERIS definition: {name}"
                )));
            }
            Some("IF" | "LOOP") => depth += 1,
            Some("IFEND" | "LOOPEND") => {
                depth = depth.checked_sub(1).ok_or(Error::InvalidFormat)?
            }
            _ => {
                if depth == 0 {
                    result.push(instruction);
                } else if call(&instruction).is_some_and(|name| {
                    name.starts_with("es.VO.") || name.starts_with("es.CHAR.NAME")
                }) || name == "ES.FOLDER.DEFINE"
                {
                    return Err(Error::Unsupported(format!(
                        "Conditional ERIS definition: {name}"
                    )));
                }
            }
        }
    }
    Ok(result)
}
