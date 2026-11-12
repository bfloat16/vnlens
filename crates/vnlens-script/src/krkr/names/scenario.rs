//! KAG compiled SCN references: StorageData appends `.scn` to the original
//! storage name (including `.ks`); KAGEnvironment saves imageFile/replay state
//! and command argument pairs. PSDInfo::_loadImages supplies composite image
//! suffixes, getExistImageNameForLayer supplies raster suffixes, and
//! SimpleAnimEffectPlugin::execCommand supplies `.tjs`. These are name hints only;
//! the archive must prove each spelling against its stored filename hash.
use super::{check, sound_candidates};
use std::{collections::BTreeSet, sync::atomic::AtomicBool};
use vnlens_core::Result;
use vnlens_middleware::psb::PsbValue;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Reference {
    Image,
    Raster,
    Composite,
    Sound,
    Scenario,
    Script,
    Movie,
}

fn argument(command: &str, field: &str) -> Option<Reference> {
    if field == "rule" {
        return Some(Reference::Raster);
    }
    if command == "simpleanim" && field == "script" {
        return Some(Reference::Script);
    }
    if !matches!(field, "file" | "storage" | "uistorage") {
        return None;
    }
    match command {
        "voice" | "bgm" | "se" | "playse" | "sound" | "loopse" | "lse" => Some(Reference::Sound),
        "image" | "graph" | "simpleanim" => Some(Reference::Raster),
        "uiload" | "mapinit" | "meswinopt" | "selopt" => Some(Reference::Composite),
        "jump" | "call" | "next" | "exit" | "scenestart" => Some(Reference::Scenario),
        "movie" | "sysmovie" => Some(Reference::Movie),
        _ => None,
    }
}

pub(super) fn candidates(
    root: &PsbValue,
    cancel: &AtomicBool,
    out: &mut BTreeSet<String>,
) -> Result<()> {
    let Some(fields) = root.as_object() else {
        return Ok(());
    };
    let Some(name) = fields.get("name").and_then(PsbValue::as_str) else {
        return Ok(());
    };
    if fields.get("scenes").and_then(PsbValue::as_list).is_none() {
        return Ok(());
    }
    let mut references = BTreeSet::from([(name, Reference::Scenario)]);
    let mut pending = vec![("", root)];
    while let Some((parent, value)) = pending.pop() {
        check(cancel)?;
        match value {
            PsbValue::Object(fields) => {
                let command = fields.get("tagname").and_then(PsbValue::as_str);
                for (field, value) in fields {
                    check(cancel)?;
                    if let Some(text) = value.as_str() {
                        let reference = match (parent, field.as_str()) {
                            ("imageFile", "file") => Some(Reference::Image),
                            ("replay", "filename") => Some(Reference::Sound),
                            ("nexts" | "selects", "storage") => Some(Reference::Scenario),
                            ("_init", "storage") => Some(Reference::Composite),
                            (_, "rule") => Some(Reference::Raster),
                            _ => command.and_then(|command| argument(command, field)),
                        };
                        if let Some(reference) = reference {
                            references.insert((text, reference));
                        }
                    }
                    pending.push((field, value));
                }
            }
            PsbValue::List(values) => {
                if let Some(command) = values.first().and_then(PsbValue::as_str) {
                    for pair in values[1..].as_chunks::<2>().0 {
                        check(cancel)?;
                        if let (Some(field), Some(value)) = (pair[0].as_str(), pair[1].as_str())
                            && let Some(reference) = argument(command, field)
                        {
                            references.insert((value, reference));
                        }
                    }
                }
                pending.extend(values.iter().map(|value| (parent, value)));
            }
            _ => {}
        }
    }
    // Saved environments repeat the same references across many lines/texts.
    // Expand each distinct reference once, without interpreting expressions.
    for (value, reference) in references {
        check(cancel)?;
        add_candidates(value, reference, out);
    }
    Ok(())
}

pub(super) fn add_candidates(value: &str, reference: Reference, out: &mut BTreeSet<String>) {
    let value = value.trim();
    if value.is_empty()
        || value.starts_with(['@', '&', '%', '*'])
        || value.contains("${")
        || value.chars().any(char::is_control)
    {
        return;
    }
    if reference == Reference::Sound {
        sound_candidates(value, out);
        return;
    }
    out.insert(value.into());
    if reference == Reference::Scenario {
        out.insert(format!("{value}.scn"));
        return;
    }
    let leaf = value.rsplit(['/', char::from(92)]).next().unwrap_or(value);
    let base = if let Some((stem, _)) = value.rsplit_once('.')
        && leaf.contains('.')
    {
        if reference != Reference::Raster {
            return;
        }
        // getExistFileNameAutoExtFill uses chopStorageExt before trying
        // the raster suffixes, even when the input has an extension.
        stem
    } else {
        value
    };
    let suffixes: &[&str] = match reference {
        Reference::Image => &[
            ".png", ".tlg", ".tlg5", ".tlg6", ".jpeg", ".jpg", ".bmp", ".asd", ".emf", ".stage",
            ".stand", ".sinfo", ".event",
        ],
        Reference::Composite => &[".psd", ".pimg", ".pbd", ".txt", ".tjs"],
        Reference::Raster => &[".png", ".tlg", ".tlg5", ".tlg6", ".jpeg", ".jpg", ".bmp"],
        Reference::Script => &[".tjs"],
        Reference::Movie => &[".mpg", ".wmv", ".mp4"],
        Reference::Sound | Reference::Scenario => &[],
    };
    for suffix in suffixes {
        out.insert(format!("{base}{suffix}"));
    }
}

#[cfg(test)]
#[path = "../../../tests/krkr/names/scenario.rs"]
mod tests;
