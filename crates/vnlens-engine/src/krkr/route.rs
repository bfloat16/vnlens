//! KiriKiri / KiriKiri Z resource and XP3 archive routing.
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
    if matches!(bytes.get(..4), Some(b"TLG0" | b"TLG5" | b"TLG6")) {
        Some(Image("tlg/krkr"))
    } else if bytes.starts_with(b"TJS2")
        || bytes.starts_with(b"\xfe\xfe")
        || bytes.starts_with(b"PSB\0")
        || bytes.starts_with(b"mdf\0")
    {
        // Configured middleware containers keep their archive route.
        route
            .archive()
            .map(|a| ResourceRoute::Archive(Box::new(a)))
            .or(Some(Script("script/krkr")))
    } else {
        None
    }
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    (route.ext == "xp3").then(|| route.archive_with("xp3/krkr"))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script};
    match route.ext {
        "tlg" | "tlg5" | "tlg6" => Some(Image("tlg/krkr")),
        "tjs" | "ks" | "scn" | "asd" | "psb" | "m" => Some(Script("script/krkr")),
        _ => None,
    }
}
