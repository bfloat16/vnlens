//! Background dataset generation. Only complete, unambiguous records enter the
//! index, and only after their original-format voice resource was written.

use crate::{
    Progress, Record, Stage,
    resources::{Resources, check, normalized},
    yuris,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, atomic::AtomicBool};
use vnlens_core::{Error, ResourceRoute, Result};
use vnlens_engine::{Engine, Identification};

#[must_use]
pub fn supports(engine: Engine) -> bool {
    engine == Engine::Yuris
}

/// Generates one game instance into an empty output directory. The host owns
/// directory selection and must keep the output exclusive for this operation.
/// Cancellation returns Error::Cancelled; an unfinished run has no index.json.
/// Per-resource failures are reported and excluded while later resources continue.
pub fn generate(
    game: Arc<Identification>,
    output: &Path,
    cancel: Arc<AtomicBool>,
    mut report: impl FnMut(Progress, Option<String>),
) -> Result<Progress> {
    if !supports(game.engine) {
        return Err(Error::Unsupported(
            "Dataset generation is not implemented for this engine".into(),
        ));
    }
    check(&cancel)?;
    std::fs::create_dir_all(output)?;
    if std::fs::read_dir(output)?.next().transpose()?.is_some() {
        return Err(Error::Unsupported(
            "Choose an empty folder for the dataset".into(),
        ));
    }
    let output = output.canonicalize()?;
    vnlens_archive::init();
    vnlens_script::init();
    let mut progress = Progress::default();
    report(progress, None);
    let resources = Resources::collect(game, &output, cancel.clone(), &mut progress, &mut report)?;
    let config = yuris::Config::load(&resources, &cancel)?;
    let dialogues = yuris::collect(&resources, &config, &cancel, &mut progress, &mut report)?;
    let mut voices: BTreeMap<String, Option<usize>> = BTreeMap::new();
    let mut voice_aliases: BTreeMap<String, Option<usize>> = BTreeMap::new();
    for (id, item) in resources.items.iter().enumerate() {
        check(&cancel)?;
        if resources.find(&item.name) != Some(id) {
            continue;
        }
        if !matches!(
            item.route,
            ResourceRoute::Audio(_) | ResourceRoute::Media { .. }
        ) {
            continue;
        }
        for (name, index) in std::iter::once((normalized(&item.name), &mut voices)).chain(
            config
                .voice_resource_alias(&item.name)
                .map(|name| (name, &mut voice_aliases)),
        ) {
            for key in [
                name.clone(),
                name.rsplit_once('.')
                    .map_or(name.as_str(), |(stem, _)| stem)
                    .to_owned(),
            ] {
                index
                    .entry(key)
                    .and_modify(|value| {
                        if *value != Some(id) {
                            *value = None;
                        }
                    })
                    .or_insert(Some(id));
            }
        }
    }
    let mut resolved = Vec::new();
    for dialogue in dialogues {
        check(&cancel)?;
        if let Some(id) = config.voice_path(&dialogue.voice).and_then(|p| {
            voices
                .get(&p)
                .or_else(|| voice_aliases.get(&p))
                .copied()
                .flatten()
        }) {
            resolved.push((dialogue, id));
        } else {
            progress.skipped += 1;
        }
    }
    let mut records = Vec::new();
    let mut written: HashMap<usize, Option<String>> = HashMap::new();
    let mut destinations = HashSet::from([String::from("index.json")]);
    let mut unique = HashSet::new();
    progress.stage = Stage::Writing;
    progress.completed = 0;
    progress.total = resolved.len();
    for (dialogue, id) in resolved {
        check(&cancel)?;
        if let Some(speaker) = config.speaker(&dialogue.speaker) {
            if let std::collections::hash_map::Entry::Vacant(slot) = written.entry(id) {
                let name = resources.items[id].name.replace('\\', "/");
                let leaf = name.rsplit('/').next().unwrap_or(&name);
                let mut filename = leaf.to_owned();
                let mut suffix = 1u64;
                while !destinations.insert(filename.to_lowercase()) {
                    let (stem, ext) = leaf.rsplit_once('.').unwrap_or((leaf, ""));
                    filename = if ext.is_empty() {
                        format!("{stem}_{suffix}")
                    } else {
                        format!("{stem}_{suffix}.{ext}")
                    };
                    suffix = suffix.checked_add(1).ok_or_else(|| {
                        Error::Unsupported("Dataset filename counter overflow".into())
                    })?;
                }
                let result = resources.write(id, &output, &filename);
                match result {
                    Ok(path) => {
                        let relative = path.strip_prefix(&output).map_err(|_| {
                            Error::Unsupported("Dataset voice escaped output directory".into())
                        })?;
                        slot.insert(Some(relative.to_string_lossy().replace('\\', "/")));
                        progress.voices += 1;
                    }
                    Err(Error::Cancelled) => return Err(Error::Cancelled),
                    Err(error) => {
                        slot.insert(None);
                        progress.failed += 1;
                        report(
                            progress,
                            Some(format!("{}: {error}", resources.items[id].name)),
                        );
                    }
                }
            }
            if let Some(Some(voice)) = written.get(&id) {
                let record = Record {
                    speaker,
                    voice: voice.clone(),
                    text: dialogue.text,
                };
                if unique.insert(record.clone()) {
                    records.push(record);
                    progress.records += 1;
                } else {
                    progress.skipped += 1;
                }
            } else {
                progress.skipped += 1;
            }
        } else {
            progress.skipped += 1;
        }
        progress.completed += 1;
        report(progress, None);
    }
    check(&cancel)?;
    vnlens_io::filesystem::write_under_with(&output, "index.json", |file| {
        let mut writer = std::io::BufWriter::new(file);
        writer.write_all(b"[\n")?;
        for (index, record) in records.iter().enumerate() {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(std::io::Error::other(Error::Cancelled));
            }
            if index != 0 {
                writer.write_all(b",\n")?;
            }
            serde_json::to_writer_pretty(&mut writer, record).map_err(std::io::Error::other)?;
        }
        writer.write_all(b"\n]\n")?;
        writer.flush()
    })
    .map_err(|error| {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            Error::Cancelled
        } else {
            Error::Io(error)
        }
    })?;
    report(progress, None);
    Ok(progress)
}
