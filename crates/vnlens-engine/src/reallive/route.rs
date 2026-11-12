//! RealLive routes reuse the verified shared G00, NWA, GAN and OVK/NWK formats.
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
    match route.ext {
        "g00" => Some(ResourceRoute::Image("g00/siglus")),
        "pdt" => Some(ResourceRoute::Image("pdt/reallive")),
        "nwa" => Some(ResourceRoute::Audio("nwa/siglus")),
        "gan" => Some(ResourceRoute::Script("script/siglus")),
        _ => None,
    }
}

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    (route.header.starts_with(&[0xd0, 1, 0, 0])).then_some(ResourceRoute::Script("script/reallive"))
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    let tag = if route.leaf == "seen.txt" {
        "seen/reallive"
    } else if matches!(route.ext, "ovk" | "nwk") {
        "voice/siglus"
    } else {
        return None;
    };
    Some(route.archive_with(tag))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    ((route.leaf.starts_with("seen") && route.ext == "txt" && route.leaf != "seen.txt")
        || route.ext == "ini")
        .then_some(ResourceRoute::Script("script/reallive"))
}

#[cfg(test)]
#[path = "../../tests/reallive/route.rs"]
mod tests;
