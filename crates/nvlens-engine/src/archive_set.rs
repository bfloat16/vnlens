//! File relationships used by archive routing and disk browsers. Companion
//! rules live in each engine's `route` module; no archive payload is read and
//! similar prefixes alone never establish a relationship.
use crate::Identification;
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
        let router = crate::detect::detector(self.engine).map(|d| &d.route);
        let mut result = Vec::new();
        for names in directories.values() {
            let mut assigned = BTreeSet::new();
            for (name, primary) in names {
                if assigned.contains(name) {
                    continue;
                }
                let group = router
                    .and_then(|r| (r.archive_set)(name, primary, names))
                    .or_else(|| {
                        self.emote
                            .then(|| crate::emote::route::archive_set(name, primary, names))
                            .flatten()
                    });
                let Some((primary_path, mut members)) = group else {
                    continue;
                };
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

#[cfg(test)]
#[path = "../tests/archive_set.rs"]
mod tests;
