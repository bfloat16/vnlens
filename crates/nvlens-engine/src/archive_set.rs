//! File relationships used by archive routing and disk browsers. These rules
//! mirror the readers' companion conventions; no archive payload is read and
//! similar prefixes alone never establish a relationship.
use crate::{Engine, Identification};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

/// One logical archive and its installed index, payload, volume or patch files.
/// Members retain their on-disk names; `primary` is the reader's entry point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveSet {
    pub primary: PathBuf,
    pub members: Vec<PathBuf>,
}

impl Identification {
    /// Groups only files supplied by the caller, without opening their contents.
    /// Missing companions are not invented; a lone file stays a normal item.
    #[must_use]
    pub fn archive_sets(&self, files: &[PathBuf]) -> Vec<ArchiveSet> {
        let mut directories = BTreeMap::<_, BTreeMap<String, &PathBuf>>::new();
        for path in files {
            if let (Some(parent), Some(name)) =
                (path.parent(), path.file_name().and_then(|s| s.to_str()))
            {
                directories
                    .entry(parent)
                    .or_default()
                    .insert(name.to_ascii_lowercase(), path);
            }
        }
        let mut result = Vec::new();
        for names in directories.values() {
            let mut assigned = BTreeSet::new();
            for (name, primary) in names {
                if assigned.contains(name) {
                    continue;
                }
                let mut members = vec![name.clone()];
                let mut primary_path = (*primary).clone();
                match self.engine {
                    Engine::SystemNnn => {
                        if let Some(stem) = name.strip_suffix(".gpk") {
                            members.push(format!("{stem}.gtb"));
                        } else if let Some(stem) = name.strip_suffix(".vpk") {
                            members.push(format!("{stem}.vtb"));
                        } else if let Some(stem) = name.strip_suffix(".gtb") {
                            let archive = format!("{stem}.gpk");
                            if names.contains_key(&archive) {
                                members.push(archive.clone());
                                primary_path = (*names[&archive]).clone();
                            }
                        } else if let Some(stem) = name.strip_suffix(".vtb") {
                            let archive = format!("{stem}.vpk");
                            if names.contains_key(&archive) {
                                members.push(archive.clone());
                                primary_path = (*names[&archive]).clone();
                            }
                        }
                    }
                    Engine::Rugp if name.ends_with(".rio") || name.contains(".rio.") => {
                        let base = name
                            .split_once(".rio.")
                            .map_or_else(|| name.clone(), |(stem, _)| format!("{stem}.rio"));
                        let Some(base_path) = names.get(&base) else {
                            continue;
                        };
                        primary_path = (*base_path).clone();
                        members = names
                            .keys()
                            .filter(|candidate| {
                                *candidate == &base
                                    || candidate.strip_prefix(&format!("{base}.")).is_some_and(
                                        |suffix| {
                                            matches!(suffix, "ici" | "ruo")
                                                || (!suffix.is_empty()
                                                    && suffix.bytes().all(|b| b.is_ascii_digit()))
                                        },
                                    )
                            })
                            .cloned()
                            .collect();
                    }
                    Engine::Exhibit => {
                        if let Some(number) = exhibit_volume(name) {
                            let base = number & !255;
                            let index = format!("res{base:04x}.grp");
                            let Some(index_path) = names.get(&index) else {
                                continue;
                            };
                            primary_path = (*index_path).clone();
                            members = names
                                .keys()
                                .filter(|candidate| {
                                    exhibit_volume(candidate)
                                        .is_some_and(|volume| volume & !255 == base)
                                })
                                .cloned()
                                .collect();
                        }
                    }
                    _ => {}
                }
                if self.emote.is_some()
                    && (name.ends_with("info.psb") || name.ends_with("info.psb.m"))
                {
                    // Same priority as EmoteArchiveInfo::find_body_path.
                    let end = name.find("_info.").or_else(|| name.find('.')).unwrap_or(0);
                    let package = &name[..end];
                    if let Some(body) = [
                        format!("{package}_body.bin"),
                        format!("{package}body.bin"),
                        format!("{package}.bin"),
                    ]
                    .into_iter()
                    .find(|candidate| names.contains_key(candidate))
                    {
                        members.push(body);
                    }
                }
                members.retain(|member| names.contains_key(member) && !assigned.contains(member));
                if members.len() < 2 {
                    continue;
                }
                let paths = members
                    .iter()
                    .filter_map(|member| names.get(member).map(|p| (*p).clone()))
                    .collect();
                assigned.extend(members);
                result.push(ArchiveSet {
                    primary: primary_path,
                    members: paths,
                });
            }
        }
        result
    }
}

fn exhibit_volume(name: &str) -> Option<u32> {
    u32::from_str_radix(name.strip_prefix("res")?.strip_suffix(".grp")?, 16).ok()
}

#[cfg(test)]
#[path = "../tests/archive_set.rs"]
mod tests;
