//! Script names are authoritative: unrelated .dat files remain unknown.
use crate::routing::{Route, Router};
use vnlens_core::{ArchiveRoute, ResourceOrigin, ResourceRoute};

pub(super) const ROUTER: Router = Router {
    archive,
    extension,
    ..Router::NONE
};

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    match route.ext {
        "nsa" => Some(route.archive_with("nsa/nscripter")),
        "sar" => Some(route.archive_with("sar/nscripter")),
        _ => None,
    }
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Audio, Script};
    match (route.leaf, route.ext) {
        ("nscript.dat", _) => Some(Script("nscript/nscripter")),
        ("nscript.zat", _) => Some(Script("zat/nscripter")),
        (_, "txt") => Some(Script("text/nscripter")),
        (_, "nbz") => Some(Audio(match route.origin {
            ResourceOrigin::File => "nbz/nscripter",
            ResourceOrigin::Entry(_) => "audio/standard",
        })),
        (_, "mp3") => Some(Audio("audio/mpeg")),
        _ => None,
    }
}
