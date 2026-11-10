//! Escu:de resource and archive routing.
use crate::routing::{Route, Router};
use nvlens_core::{ArchiveRoute, ResourceOrigin, ResourceRoute};

pub(super) const ROUTER: Router = Router {
    headerless,
    header,
    archive,
    extension,
    ..Router::NONE
};

fn headerless(route: &Route<'_>) -> Option<ResourceRoute> {
    (route.ext == "sfx").then_some(ResourceRoute::Script("sfx/escude"))
}

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    matches!(
        route.header.get(..4),
        Some(b"@cod" | b"@mes" | b"mdb\0" | b"LSF\0" | b"MOT\0" | b"mot\0" | b"acp\0")
    )
    .then_some(ResourceRoute::Script("script/escude"))
}

// ESC-ARC and its .bin script entries share an extension. The storage
// context distinguishes name-only listings; actual container magic wins.
fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    (route.ext == "bin"
        && (matches!(route.origin, ResourceOrigin::File)
            || route.header.is_empty()
            || route.header.starts_with(b"ESC-ARC")))
    .then(|| route.archive_with("bin/escude"))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::Script;
    match route.ext {
        "c" | "h" | "inc" | "txt" | "cfg" | "001" => Some(Script("text/escude")),
        "bin" | "lsf" | "mot" => Some(Script("script/escude")),
        _ => None,
    }
}
