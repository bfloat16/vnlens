//! E-mote PSB/MDF archive routing and info/body companion pairing.
use crate::routing::Route;
use nvlens_core::ArchiveRoute;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub(crate) fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    let tag = if route.leaf.ends_with("info.psb") || route.leaf.ends_with("info.psb.m") {
        "psb/emote-archive-info"
    } else if matches!(route.ext, "psb" | "m") {
        "psb/emote-resources"
    } else {
        return None;
    };
    Some(route.archive_with(tag))
}

pub(crate) fn archive_set(
    name: &str,
    primary: &Path,
    names: &BTreeMap<String, &PathBuf>,
) -> Option<(PathBuf, Vec<String>)> {
    if !name.ends_with("info.psb") && !name.ends_with("info.psb.m") {
        return None;
    }
    // Same priority as EmoteArchiveInfo::find_body_path.
    let end = name.find("_info.").or_else(|| name.find('.')).unwrap_or(0);
    let package = &name[..end];
    let body = [
        format!("{package}_body.bin"),
        format!("{package}body.bin"),
        format!("{package}.bin"),
    ]
    .into_iter()
    .find(|candidate| names.contains_key(candidate))?;
    Some((primary.to_path_buf(), vec![name.to_owned(), body]))
}
