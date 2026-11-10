//! Kaleido resource routing, PSB archive-info routing and companion pairing.
use crate::routing::{Route, Router};
use nvlens_core::{ArchiveRoute, ResourceKind, ResourceRoute};

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
    if bytes.starts_with(&[0xfa, 0xfa, b'R', b'I'])
        || bytes.starts_with(b"PSB\0")
        || bytes.starts_with(b"mzs\0")
        || bytes.starts_with(b"mdf\0")
    {
        route
            .archive()
            .map(|a| ResourceRoute::Archive(Box::new(a)))
            .or(Some(ResourceRoute::Script("script/kaleido")))
    } else {
        None
    }
}

fn entry(route: &Route<'_>) -> Option<ResourceRoute> {
    matches!(route.hint, ResourceKind::Script | ResourceKind::Data)
        .then_some(ResourceRoute::Script("script/kaleido"))
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    (route.leaf.ends_with("info.psb") || route.leaf.ends_with("info.psb.m"))
        .then(|| route.archive_with("psb/emote-archive-info"))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Script, Video};
    match route.ext {
        "webm" => Some(Video("webm/kaleido")),
        "nut" | "cnut" | "ks" | "scn" | "psb" | "m" => Some(Script("script/kaleido")),
        _ => None,
    }
}
