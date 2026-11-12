//! Kaleido resource routing, PSB archive-info routing and companion pairing.
use crate::routing::{Route, Router};
use vnlens_core::{ArchiveRoute, ResourceKind, ResourceRoute};

pub(super) const ROUTER: Router = Router {
    header,
    entry,
    archive,
    extension,
    archive_set: crate::emote::route::archive_set,
    ..Router::NONE
};

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    let bytes = route.header;
    if bytes.starts_with(&[0xfa, 0xfa, b'R', b'I']) {
        Some(ResourceRoute::Script("script/kaleido"))
    } else {
        crate::emote::route::header(route)
    }
}

fn entry(route: &Route<'_>) -> Option<ResourceRoute> {
    match route.hint {
        ResourceKind::Script => Some(ResourceRoute::Script("script/kaleido")),
        ResourceKind::Data => Some(ResourceRoute::Archive(Box::new(route.archive_with("psb")))),
        _ => None,
    }
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    crate::emote::route::archive(route)
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Script, Video};
    match route.ext {
        "webm" => Some(Video("webm/kaleido")),
        "nut" | "cnut" | "ks" | "scn" => Some(Script("script/kaleido")),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/kaleido/route.rs"]
mod tests;
