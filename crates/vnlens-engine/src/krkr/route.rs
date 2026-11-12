//! KiriKiri / KiriKiri Z resource, XP3 and PSB scenario routing.
use crate::routing::{Route, Router};
use vnlens_core::{ArchiveRoute, ResourceRoute};

pub(crate) const ROUTER: Router = Router {
    headerless,
    header,
    archive,
    extension,
    ..Router::NONE
};

fn headerless(route: &Route<'_>) -> Option<ResourceRoute> {
    (route.compose_pimg && route.ext == "pimg").then_some(ResourceRoute::Image("pimg/krkr"))
}

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script};
    let bytes = route.header;
    if matches!(bytes.get(..4), Some(b"TLG0" | b"TLG5" | b"TLG6")) {
        Some(Image("tlg/krkr"))
    } else if bytes.starts_with(b"TJS2") || bytes.starts_with(b"\xfe\xfe") {
        Some(Script("script/krkr"))
    } else {
        crate::emote::route::header(route)
    }
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    crate::emote::route::archive(route).or_else(|| match route.ext {
        "xp3" => Some(route.archive_with("xp3/krkr")),
        // KAG StorageData appends .scn to the original scenario storage name.
        "scn" => Some(route.archive_with("psb")),
        _ => None,
    })
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script};
    match route.ext {
        "tlg" | "tlg5" | "tlg6" => Some(Image("tlg/krkr")),
        "tjs" | "ks" | "asd" => Some(Script("script/krkr")),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/krkr/route.rs"]
mod tests;
