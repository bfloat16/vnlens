//! SiglusEngine resource and archive routing.
use crate::routing::{Route, Router};
use vnlens_core::{ArchiveRoute, ResourceRoute};

pub(super) const ROUTER: Router = Router {
    headerless,
    header,
    archive,
    extension,
    ..Router::NONE
};

fn headerless(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Audio, Image};
    match route.ext {
        "g00" => Some(Image("g00/siglus")),
        "nwa" => Some(Audio("nwa/siglus")),
        _ => None,
    }
}

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
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
    matches!(route.ext, "ss" | "gan").then_some(ResourceRoute::Script("script/siglus"))
}
