//! rUGP resource routing, RIO archive routing and companion volume sets.
use crate::routing::{Route, Router};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use vnlens_core::{ArchiveRoute, ResourceKind, ResourceOrigin, ResourceRoute};
use vnlens_io::BinaryReader;

pub(super) const ROUTER: Router = Router {
    header,
    entry,
    archive,
    extension,
    archive_set,
    ..Router::NONE
};

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script};
    let bytes = route.header;
    if matches!(route.origin, ResourceOrigin::File)
        && bytes
            .get(..4)
            .is_some_and(|header| matches!(BinaryReader::u32_le(header), 0x1edb_927c | 0x596e_32cd))
    {
        return Some(ResourceRoute::Archive(Box::new(
            route.archive_with("rio/rugp"),
        )));
    }
    if bytes.starts_with(b"VNLRSI\0\x01") {
        Some(Image("frame/rugp"))
    } else if bytes.len() >= 4
        && matches!(
            BinaryReader::u32_le(bytes),
            0x29f6_cba4 | 0x1edb_927c | 0x596e_32cd
        )
    {
        // rUGP's serialized class decides which domain consumes an object.
        Some(if route.hint == ResourceKind::Image {
            Image("image/rugp")
        } else {
            Script("object/rugp")
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
    (route.ext == "rio" && matches!(route.origin, ResourceOrigin::File))
        .then(|| route.archive_with("rio/rugp"))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Audio, Image, Script};
    match route.ext {
        "oor" | "coptimizedobs" | "coptimizedobsforr" => Some(Audio("oor/rugp")),
        "rio" if matches!(route.origin, ResourceOrigin::Entry(_)) => Some(Script("object/rugp")),
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
