//! MAGES formats are dispatched only within an identified libMgs game.
use crate::routing::{Route, Router};
use vnlens_core::{ArchiveRoute, ResourceKind, ResourceRoute};

pub(super) const ROUTER: Router = Router {
    header,
    archive,
    extension,
    ..Router::NONE
};

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    if route.header.starts_with(b"mcfa") {
        // MCF bonus applications can share an install directory and .mpk
        // extension. Their container is not a libMgs MPK archive.
        Some(ResourceRoute::Other(ResourceKind::Archive))
    } else if route.header.starts_with(b"MPK\0") {
        Some(ResourceRoute::Archive(Box::new(
            route.archive_with("mpk/mages"),
        )))
    } else if route.header.starts_with(b"SC3\0") {
        Some(ResourceRoute::Script("scx/mages"))
    } else if route.header.starts_with(b"MES\0") {
        Some(ResourceRoute::Script("msb/mages"))
    } else {
        None
    }
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    (route.ext == "mpk").then(|| route.archive_with("mpk/mages"))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    match route.ext {
        "scx" => Some(ResourceRoute::Script("scx/mages")),
        "msb" => Some(ResourceRoute::Script("msb/mages")),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/mages/route.rs"]
mod tests;
