//! C,system case-sensitive record routing, split archive routing and companion sets.
use crate::routing::{Route, Router};
use nvlens_core::{ArchiveRoute, ResourceRoute};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub(super) const ROUTER: Router = Router {
    headerless,
    archive,
    extension,
    archive_set,
    ..Router::NONE
};

/// These records have no magic. Their archive type byte is case-sensitive.
fn headerless(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script};
    let legacy = route.options.numbers.get("csystem_legacy") == Some(&1);
    Some(match route.stored_ext {
        "cimg" => Image("image/csystem"),
        "b0" | "n0" | "o0" => Image(if legacy {
            "image-legacy/csystem"
        } else {
            "image/csystem"
        }),
        "c0" if legacy => Script("animation-legacy/csystem"),
        "a0" => Script("script/csystem"),
        "f0" => Script("f0/csystem"),
        "l0" => Script("l0/csystem"),
        "m0" => Script("m0/csystem"),
        "e0" => Script("e0/csystem"),
        "r0" => Script("r0/csystem"),
        "s0" => Script("s0/csystem"),
        "B0" => Script("properties/csystem"),
        "C0" => Script("references/csystem"),
        "x0" => Script("x0/csystem"),
        "q0" => Script("q0/csystem"),
        "t0" => Script("t0/csystem"),
        "v0" => Script("v0/csystem"),
        "c0" => Script("animation/csystem"),
        "i0" => Script("movie-path/csystem"),
        _ => return None,
    })
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    (route.ext == "dat" && archive_name(route.name)).then(|| route.archive_with("dat/csystem"))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Audio, Video};
    match route.ext {
        "j0" | "k0" | "u0" => Some(Audio("audio/standard")),
        "y0" => Some(Video("ffmpeg")),
        _ => None,
    }
}

fn archive_set(
    name: &str,
    primary: &Path,
    names: &BTreeMap<String, &PathBuf>,
) -> Option<(PathBuf, Vec<String>)> {
    let mut members = vec![name.to_owned()];
    if name == "data00.dat" {
        members.extend(
            names
                .keys()
                .filter(|candidate| {
                    candidate
                        .strip_prefix("data")
                        .and_then(|s| s.strip_suffix(".dat"))
                        .is_some_and(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
                })
                .cloned(),
        );
        return Some((primary.to_path_buf(), members));
    }
    let data: &[&str] = match name {
        "arc01.dat" => &["arc04.dat"],
        "arc02.dat" => &["arc05.dat", "arc05a.dat", "arc05b.dat"],
        "arc03.dat" => &["arc06.dat"],
        "arc07.dat" => &["arc08.dat", "arc08a.dat"],
        "arc09.dat" => &["arc10.dat"],
        _ => return None,
    };
    let path = data.iter().find_map(|name| names.get(*name))?;
    members.extend(data.iter().copied().map(str::to_owned));
    Some(((*path).clone(), members))
}

fn archive_name(name: &str) -> bool {
    let leaf = name.rsplit('/').next().unwrap_or(name);
    let stem = leaf.strip_suffix(".dat").unwrap_or("");
    stem.strip_prefix("arc").is_some_and(|s| {
        let s = s.strip_suffix(['a', 'b']).unwrap_or(s);
        s.len() == 2 && s.bytes().all(|c| c.is_ascii_digit())
    }) || stem
        .strip_prefix("data")
        .is_some_and(|s| s == "00" || s.len() == 3 && s.bytes().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
#[path = "../../tests/csystem/route.rs"]
mod tests;
