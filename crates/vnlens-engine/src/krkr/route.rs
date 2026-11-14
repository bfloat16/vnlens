//! KiriKiri / KiriKiri Z resource, XP3 and PSB scenario routing.
use crate::routing::{Route, Router};
use vnlens_core::{ArchiveRoute, ResourceRoute};

pub(crate) const ROUTER: Router = Router {
    header,
    archive,
    extension,
    ..Router::NONE
};

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script};
    let bytes = route.header;
    if bytes.starts_with(b"XP3\r\n \n\x1a\x8bg\x01") {
        Some(ResourceRoute::Archive(Box::new(
            route.archive_with("xp3/krkr"),
        )))
    } else if matches!(bytes.get(..4), Some(b"TLG0" | b"TLG5" | b"TLG6")) {
        Some(Image("tlg/krkr"))
    } else if bytes.starts_with(b"TJS2") || bytes.starts_with(b"\xfe\xfe") {
        Some(Script("script/krkr"))
    } else {
        crate::emote::route::header(route)
    }
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    if route.compose_pimg && route.ext == "pimg" {
        return None;
    }
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
        "pimg" if route.compose_pimg => Some(Image("pimg/krkr")),
        "tlg" | "tlg5" | "tlg6" => Some(Image("tlg/krkr")),
        "tjs" | "ks" | "asd" => Some(Script("script/krkr")),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/krkr/route.rs"]
mod tests;
