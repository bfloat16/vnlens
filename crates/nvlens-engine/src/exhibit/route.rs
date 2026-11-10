//! ExHIBIT resource routing and hex-group GRP volume sets.
//! UxAdvSystem::createMovieFilename (sub_100C1D80) defaults to .mpg and
//! accepts an explicit extension. playVideo passes the disk path through to
//! IGraphBuilder::RenderFile (sub_48A6F0), without an engine-specific wrapper.
use crate::routing::{Route, Router};
use nvlens_core::{ArchiveRoute, ResourceRoute};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub(super) const ROUTER: Router = Router {
    header,
    archive,
    extension,
    archive_set,
    ..Router::NONE
};

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script};
    if route.header.starts_with(b"GYU\x1a") {
        Some(Image("gyu/exhibit"))
    } else if route.header.get(28..32) == Some(b"DLT\0") {
        Some(Image("dlt/exhibit"))
    } else if route.header.starts_with(b"\0DLR") {
        Some(Script("rld/exhibit"))
    } else {
        None
    }
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    (route.ext == "grp").then(|| route.archive_with("grp/exhibit"))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script};
    match route.ext {
        "gyu" | "lvg" => Some(Image("gyu/exhibit")),
        "dlt" => Some(Image("dlt/exhibit")),
        "rld" | "rnf" | "ini" => Some(Script("rld/exhibit")),
        _ => None,
    }
}

fn archive_set(
    name: &str,
    _primary: &Path,
    names: &BTreeMap<String, &PathBuf>,
) -> Option<(PathBuf, Vec<String>)> {
    let base = volume(name)? & !255;
    let index = format!("res{base:04x}.grp");
    let index_path = names.get(&index)?;
    let members = names
        .keys()
        .filter(|candidate| volume(candidate).is_some_and(|v| v & !255 == base))
        .cloned()
        .collect();
    Some(((*index_path).clone(), members))
}

fn volume(name: &str) -> Option<u32> {
    u32::from_str_radix(name.strip_prefix("res")?.strip_suffix(".grp")?, 16).ok()
}
