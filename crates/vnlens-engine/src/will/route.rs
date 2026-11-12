//! AdvHD v2 resource and ARC/AR2 archive routing.
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
    (route.ext == "ws2").then_some(ResourceRoute::Script("ws2/will"))
}

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    (route.header.starts_with(b"PNAP") || route.header.starts_with(b"PNAS"))
        .then_some(ResourceRoute::Image("pna/will"))
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    matches!(route.ext, "arc" | "ar2").then(|| route.archive_with("arc/willv2"))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script};
    match route.ext {
        "pna" | "mos" => Some(Image("pna/will")),
        "json" => Some(Script("json/will")),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/will/route.rs"]
mod tests;
