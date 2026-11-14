//! SiglusEngine resource and archive routing.
use crate::routing::{Route, Router};
use vnlens_core::{ArchiveRoute, ResourceRoute};

pub(super) const ROUTER: Router = Router {
    header,
    archive,
    extension,
    ..Router::NONE
};

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    let archive = match route.header.get(..4) {
        Some(b"\x5c\0\0\0") => Some("pck/siglus"),
        Some(b"\xa8\0\0\0") => Some("omv/siglus"),
        _ => None,
    };
    if let Some(tag) = archive {
        return Some(ResourceRoute::Archive(Box::new(route.archive_with(tag))));
    }
    (route.header.starts_with(b"\x84\0\0\0")
        || route.header.starts_with(b"\x10\x27\0\0\x10\x27\0\0"))
    .then_some(ResourceRoute::Script("script/siglus"))
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    let tag = if route.ext == "pck" {
        "pck/siglus"
    } else if matches!(route.ext, "ovk" | "nwk") {
        "voice/siglus"
    } else if route.ext == "omv" {
        "omv/siglus"
    } else if route.leaf == "gameexe.dat" {
        "gameexe/siglus"
    } else {
        return None;
    };
    Some(route.archive_with(tag))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Audio, Image, Script};
    match route.ext {
        "g00" => Some(Image("g00/siglus")),
        "nwa" => Some(Audio("nwa/siglus")),
        "ss" | "gan" => Some(Script("script/siglus")),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/siglus/route.rs"]
mod tests;
