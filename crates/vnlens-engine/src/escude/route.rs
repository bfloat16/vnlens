//! Escu:de resource and archive routing.
use crate::routing::{Route, Router};
use vnlens_core::{ArchiveRoute, ResourceOrigin, ResourceRoute};

pub(super) const ROUTER: Router = Router {
    header,
    archive,
    extension,
    ..Router::NONE
};

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    if route.header.starts_with(b"ESC-ARC") {
        return Some(ResourceRoute::Archive(Box::new(
            route.archive_with("bin/escude"),
        )));
    }
    matches!(
        route.header.get(..4),
        Some(b"@cod" | b"@mes" | b"mdb\0" | b"LSF\0" | b"MOT\0" | b"mot\0" | b"acp\0")
    )
    .then_some(ResourceRoute::Script("script/escude"))
}

// ESC-ARC disk files and their .bin script entries share a suffix. The
// storage context selects a stable route without opening either payload.
fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    (route.ext == "bin" && matches!(route.origin, ResourceOrigin::File))
        .then(|| route.archive_with("bin/escude"))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::Script;
    match route.ext {
        "sfx" => Some(Script("sfx/escude")),
        "c" | "h" | "inc" | "txt" | "cfg" | "001" => Some(Script("text/escude")),
        "bin" | "lsf" | "mot" => Some(Script("script/escude")),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/escude/route.rs"]
mod tests;
