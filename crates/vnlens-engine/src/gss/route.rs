//! GSS indices retain extensionless native member names. The bank supplies
//! script/audio index kinds; raster files use their logical standard headers.
use crate::routing::{Route, Router};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use vnlens_core::{ArchiveRoute, ResourceKind, ResourceOrigin, ResourceRoute};

pub(super) const ROUTER: Router = Router {
    archive,
    extension,
    header,
    entry,
    archive_set,
    ..Router::NONE
};
fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    (route.ext == "bin").then(|| route.archive_with("lsdarc/gss"))
}
fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    Some(match route.ext {
        "obj" => ResourceRoute::Script("scr/gss"),
        "opu" => ResourceRoute::Audio("opus/gss"),
        _ => return None,
    })
}
fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    Some(if route.header.starts_with(b"SCR 3.00") {
        ResourceRoute::Script("scr/gss")
    } else if route.header.starts_with(&[1, 0, 0, 0x80]) {
        ResourceRoute::Audio("opus/gss")
    } else {
        return None;
    })
}
fn entry(route: &Route<'_>) -> Option<ResourceRoute> {
    match route.origin {
        ResourceOrigin::Entry(ResourceKind::Script) => Some(ResourceRoute::Script("scr/gss")),
        _ => None,
    }
}
fn archive_set(
    name: &str,
    _: &Path,
    names: &BTreeMap<String, &PathBuf>,
) -> Option<(PathBuf, Vec<String>)> {
    let (stem, ext) = name.rsplit_once('.')?;
    if !matches!(ext, "bin" | "arc") {
        return None;
    }
    let index = format!("{stem}.bin");
    let data = format!("{stem}.arc");
    let primary = names.get(&index)?;
    names.get(&data)?;
    Some(((*primary).clone(), vec![index, data]))
}
