//! Propeller Stuff resource and MPK archive routing.
use crate::routing::{Route, Router};
use vnlens_core::{ArchiveRoute, ResourceRoute};

pub(super) const ROUTER: Router = Router {
    archive,
    extension,
    ..Router::NONE
};

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    (route.ext == "mpk").then(|| route.archive_with("mpk/propeller"))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script};
    match route.ext {
        "mgr" => Some(Image("image/propeller-mgr")),
        "msc" => Some(Script("msc/propeller")),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/propeller/route.rs"]
mod tests;
