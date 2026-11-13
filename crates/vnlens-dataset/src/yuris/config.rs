//! Project definitions reached through YSLB, not hard-coded YSTB filenames.
//! ES.FOLDER.DEFINE assigns the ERIS folder matrix at [38,13] for foreground
//! voices. es.VO.PATHDEF records four case-insensitive prefixes and a folder;
//! es.VO.PATH.SEARCH takes the first matching definition (es_soundvo.yst).
//! Character keys are identities; replacement display strings are not used.

use super::expression::{argument, call, field, integer, string};
use crate::resources::check;
use crate::resources::normalized;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicBool;
use vnlens_core::{Error, ResourceResolver, Result};
use vnlens_script::ir::{ArgName, Instruction, Script, Value};

#[derive(Debug)]
struct VoiceRule {
    prefix: String,
    folder: String,
}

#[derive(Debug, Default)]
pub(crate) struct Config {
    pub(super) names: BTreeSet<String>,
    pub(super) markers: BTreeSet<String>,
    voice_root: String,
    voice_rules: Vec<VoiceRule>,
    other_folder: String,
    legacy_voice_lookup: bool,
    identities: BTreeMap<String, Option<String>>,
    pub(super) entry_points: BTreeMap<String, BTreeSet<u64>>,
}

impl Config {
    pub fn load(resources: &dyn ResourceResolver, cancel: &AtomicBool) -> Result<Self> {
        let labels = script(resources, "ysbin/ysl.ybn")?;
        let mut config = Self::default();
        for label in &labels.instructions {
            check(cancel)?;
            if let (Some(id), Some(Value::InstructionTarget(target))) = (
                field(&label.args, ArgName::ScriptId).and_then(integer),
                field(&label.args, ArgName::Instruction),
            ) {
                config
                    .entry_points
                    .entry(format!("ysbin/yst{id:05}.ybn"))
                    .or_default()
                    .insert(*target);
            }
        }
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
                        let display = argument(&instruction, "PSTR2").and_then(string);
                        let identity = character_identity(&name, display.as_deref());
                        config
                            .identities
                            .entry(character_key(&name).to_owned())
                            .and_modify(|previous| {
                                if *previous != identity {
                                    *previous = None;
                                }
                            })
                            .or_insert(identity);
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
        // Earlier ERIS projects register the same startup definition with this
        // Japanese label. Select its declared entry, never a guessed script ID.
        let voice_definition = if labels.instructions.iter().any(|instruction| {
            field(&instruction.args, ArgName::Name)
                .and_then(string)
                .as_deref()
                == Some("ES.VOICE.DEFINE")
        }) {
            "ES.VOICE.DEFINE"
        } else {
            "ボイス定義"
        };
        config.legacy_voice_lookup = voice_definition == "ボイス定義";
        for instruction in definition(resources, &labels, voice_definition, cancel)? {
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
                    for prefix in prefixes.drain(..) {
                        config.voice_rules.push(VoiceRule {
                            prefix,
                            folder: folder.clone(),
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

    /// Character declarations retain the source key and its display replacement
    /// separately. Voice groups and other dialogue cannot establish an identity.
    pub fn speaker(&self, speaker: &str) -> Option<String> {
        self.identities
            .get(speaker)
            .cloned()
            .unwrap_or_else(|| super::text::identity(speaker).then(|| speaker.to_owned()))
    }

    pub fn voice_path(&self, reference: &str) -> Option<String> {
        let reference = normalized(reference);
        let folder = self
            .voice_rules
            .iter()
            .find(|rule| reference.starts_with(&rule.prefix))
            .map_or(self.other_folder.as_str(), |rule| rule.folder.as_str());
        let path = format!("{}{folder}{reference}", self.voice_root);
        virtual_path(&path)
    }

    /// Earlier VoiceSet references omit the chapter directories beneath the
    /// declared voice root. Keep exact paths first; aliases require uniqueness.
    pub fn voice_resource_alias(&self, name: &str) -> Option<String> {
        if !self.legacy_voice_lookup {
            return None;
        }
        let root = format!("{}/", virtual_path(&self.voice_root)?);
        let name = virtual_path(name)?;
        let relative = name.strip_prefix(&root)?;
        let (_, leaf) = relative.rsplit_once('/')?;
        Some(format!("{root}{leaf}"))
    }
}

fn virtual_path(path: &str) -> Option<String> {
    let path = normalized(path);
    let mut parts = Vec::new();
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

fn character_key(name: &str) -> &str {
    let name = name.trim();
    name.strip_prefix('【')
        .and_then(|s| s.strip_suffix('】'))
        .unwrap_or(name)
        .trim()
}

/// Composite project keys carry an identity and an explicit display alias.
/// es.CHAR.NAME PSTR is the key; PSTR2 is the replacement display (es_text).
/// For example, D＠A displayed as A belongs to D, even when A is also a character.
/// Resolve only the unique identity component remaining after that replacement;
/// absent, dynamic or conflicting display definitions leave the key ambiguous.
fn character_identity(name: &str, display: Option<&str>) -> Option<String> {
    let key = character_key(name);
    if super::text::identity(key) {
        return Some(key.to_owned());
    }
    if key.contains(['＆', '&']) {
        return None;
    }
    // Delimited shorthand tokens (e.g. @x@) do not name an identity component.
    if key.split(['＠', '／']).any(|part| part.trim().is_empty()) {
        return None;
    }
    let display = character_key(display?);
    let candidates = key
        .split(['＠', '／'])
        .map(str::trim)
        .filter(|part| *part != display && super::text::identity(part))
        .collect::<BTreeSet<_>>();
    if candidates.len() == 1 {
        candidates.first().map(|s| (*s).to_owned())
    } else {
        None
    }
}

fn script(resources: &dyn ResourceResolver, name: &str) -> Result<Script> {
    let bytes = resources
        .read_resource(name)?
        .ok_or_else(|| Error::Unsupported(format!("Missing YU-RIS companion: {name}")))?;
    vnlens_script::disassemble_as("ybn/yuris", &bytes, Some(resources))?
        .ok_or_else(|| Error::Unsupported(format!("Not a YU-RIS script: {name}")))
}

fn definition(
    resources: &dyn ResourceResolver,
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
    let Some(Value::InstructionTarget(start)) = field(&target.args, ArgName::Instruction) else {
        return Err(Error::InvalidFormat);
    };
    let script = script(resources, &format!("ysbin/yst{id:05}.ybn"))?;
    let start = usize::try_from(*start).map_err(|_| Error::InvalidFormat)?;
    if start >= script.instructions.len() {
        return Err(Error::InvalidFormat);
    }
    let instructions = script.instructions.into_iter().skip(start);
    // Some projects initialize unrelated counters in loops after the voice
    // declarations. Those do not change the mapping; conditional definitions
    // themselves cannot be flattened without knowing the runtime state.
    let mut result = Vec::new();
    let mut depth = 0usize;
    let mut terminated = false;
    for instruction in instructions {
        check(cancel)?;
        match instruction.opcode.native_mnemonic.as_deref() {
            Some("RETURN" | "END") if depth == 0 => {
                terminated = true;
                break;
            }
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
    if !terminated || depth != 0 {
        return Err(Error::InvalidFormat);
    }
    Ok(result)
}

#[cfg(test)]
#[path = "../../tests/yuris/config.rs"]
mod tests;
