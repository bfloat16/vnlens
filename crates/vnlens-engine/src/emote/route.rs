//! E-mote PSB/MDF archive routing and info/body companion pairing.
use crate::routing::{Route, Router};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use vnlens_core::{ArchiveRoute, ResourceRoute};

pub(crate) const ROUTER: Router = Router {
    header,
    archive,
    archive_set,
    ..Router::NONE
};

pub(crate) fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    matches!(
        route.header.get(..4),
        Some(b"PSB\0" | b"mdf\0" | b"mzs\0" | b"PSZ\0")
    )
    .then(|| {
        ResourceRoute::Archive(Box::new(route.archive_with(if info_name(route.leaf) {
            "psb/archive-info"
        } else {
            "psb"
        })))
    })
}

pub(crate) fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    let tag = if info_name(route.leaf) {
        "psb/archive-info"
    } else if matches!(
        route.ext,
        "psb" | "m" | "mdf" | "mzs" | "psz" | "pimg" | "mmo" | "emtbytes" | "mtn" | "dpak"
    ) {
        "psb"
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
    if !info_name(name) {
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

pub(crate) fn info_name(name: &str) -> bool {
    let name = [".m", ".mdf", ".mzs", ".psz"]
        .into_iter()
        .find_map(|suffix| name.strip_suffix(suffix))
        .unwrap_or(name);
    name.ends_with("info.psb")
}

#[cfg(test)]
#[path = "../../tests/emote/route.rs"]
mod tests;
