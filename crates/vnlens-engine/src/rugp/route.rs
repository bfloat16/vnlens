//! rUGP resource routing, RIO archive routing and companion volume sets.
use crate::routing::{Route, Router};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use vnlens_core::{ArchiveRoute, ResourceKind, ResourceOrigin, ResourceRoute};
use vnlens_io::BinaryReader;

pub(super) const ROUTER: Router = Router {
    headerless,
    header,
    entry,
    archive,
    extension,
    archive_set,
};

fn headerless(route: &Route<'_>) -> Option<ResourceRoute> {
    matches!(route.ext, "oor" | "coptimizedobs" | "coptimizedobsforr")
        .then_some(ResourceRoute::Audio("oor/rugp"))
}

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script};
    let bytes = route.header;
    if bytes.starts_with(b"VNLRSI\0\x01") {
        Some(Image("frame/rugp"))
    } else if bytes.len() >= 4
        && matches!(
            BinaryReader::u32_le(bytes),
            0x29f6_cba4 | 0x1edb_927c | 0x596e_32cd
        )
        && !(matches!(route.origin, ResourceOrigin::File) && route.ext == "rio")
    {
        // rUGP's serialized class decides which domain consumes an object.
        Some(match (route.hint, route.ext) {
            (ResourceKind::Image, _)
            | (_, "cr6ti" | "cr6tix" | "crmti" | "cs5i" | "csbm" | "cicon") => Image("image/rugp"),
            _ => Script("object/rugp"),
        })
    } else {
        None
    }
}

fn entry(route: &Route<'_>) -> Option<ResourceRoute> {
    matches!(route.hint, ResourceKind::Script | ResourceKind::Data)
        .then_some(ResourceRoute::Script("object/rugp"))
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    (route.ext == "rio").then(|| route.archive_with("rio/rugp"))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script};
    match route.ext {
        "cr6ti" | "cr6tix" | "crmti" | "cs5i" | "csbm" | "cicon" => Some(Image("image/rugp")),
        "crsi_frame" => Some(Image("frame/rugp")),
        "crsa" | "cprocessocean" | "cstdb" | "crsi" | "cs5rfont" => Some(Script("object/rugp")),
        _ => None,
    }
}

fn archive_set(
    name: &str,
    _primary: &Path,
    names: &BTreeMap<String, &PathBuf>,
) -> Option<(PathBuf, Vec<String>)> {
    if !name.ends_with(".rio") && !name.contains(".rio.") {
        return None;
    }
    let base = name
        .split_once(".rio.")
        .map_or_else(|| name.to_owned(), |(stem, _)| format!("{stem}.rio"));
    let base_path = names.get(&base)?;
    let members = names
        .keys()
        .filter(|candidate| {
            *candidate == &base
                || candidate
                    .strip_prefix(&format!("{base}."))
                    .is_some_and(|suffix| {
                        matches!(suffix, "ici" | "ruo")
                            || (!suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
                    })
        })
        .cloned()
        .collect();
    Some(((*base_path).clone(), members))
}

#[cfg(test)]
#[path = "../../tests/rugp/route.rs"]
mod tests;
