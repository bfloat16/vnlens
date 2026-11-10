//! Propeller Stuff resource and MPK archive routing.
use crate::routing::{Route, Router};
use vnlens_core::{ArchiveRoute, ResourceRoute};

pub(super) const ROUTER: Router = Router {
    headerless,
    archive,
    ..Router::NONE
};

fn headerless(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script};
    match route.ext {
        "mgr" => Some(Image("image/propeller-mgr")),
        "msc" => Some(Script("msc/propeller")),
        _ => None,
    }
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    (route.ext == "mpk").then(|| route.archive_with("mpk/propeller"))
}
