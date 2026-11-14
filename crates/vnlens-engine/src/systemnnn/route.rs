//! SystemNNN resource routing, GPK/VPK archive routing and GTB/VTB companion sets.
use crate::routing::{Route, Router};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use vnlens_core::{ArchiveRoute, ResourceRoute};

pub(super) const ROUTER: Router = Router {
    header,
    archive,
    extension,
    archive_set,
    ..Router::NONE
};

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Audio, Image};
    let bytes = route.header;
    if bytes.starts_with(b"PNG ")
        || bytes.starts_with(b"JPEG ")
        || bytes.starts_with(b"BMP ")
        || (bytes.starts_with(b"IF PACKTYPE==") && bytes.get(44..48) == Some(b"BMP "))
    {
        Some(Image("dwq/systemnnn"))
    } else if (bytes.starts_with(b"IF PACKTYPE==")
        && matches!(bytes.get(44..48), Some(b"WAV " | b"OGG ")))
        || bytes.starts_with(b"                OGG ")
    {
        Some(Audio("vaw/systemnnn"))
    } else {
        None
    }
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    let tag = match route.ext {
        "gpk" => "gpk/systemnnn",
        "vpk" => "vpk/systemnnn",
        _ => return None,
    };
    Some(route.archive_with(tag))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Audio, Image, Script};
    match route.ext {
        "spt" => Some(Script("spt/systemnnn")),
        "fxf" => Some(Script("fxf/systemnnn")),
        "dwq" => Some(Image("dwq/systemnnn")),
        "vaw" | "wgq" => Some(Audio("vaw/systemnnn")),
        "xtx" | "mml" => Some(Script("text/systemnnn")),
        _ => None,
    }
}

fn archive_set(
    name: &str,
    primary: &Path,
    _names: &BTreeMap<String, &PathBuf>,
) -> Option<(PathBuf, Vec<String>)> {
    let companion = if let Some(stem) = name.strip_suffix(".gpk") {
        format!("{stem}.gtb")
    } else {
        let stem = name.strip_suffix(".vpk")?;
        format!("{stem}.vtb")
    };
    Some((primary.to_path_buf(), vec![name.to_owned(), companion]))
}

#[cfg(test)]
#[path = "../../tests/systemnnn/route.rs"]
mod tests;
