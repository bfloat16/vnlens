//! YU-RIS resource and YPF archive routing.
use crate::routing::{Route, Router};
use vnlens_core::{ArchiveRoute, ResourceRoute};

pub(super) const ROUTER: Router = Router {
    headerless,
    header,
    archive,
    extension,
    ..Router::NONE
};

fn headerless(route: &Route<'_>) -> Option<ResourceRoute> {
    (route.ext == "txt" && route.name.split('/').any(|part| part == "scenario"))
        .then_some(ResourceRoute::Script("scenario/yuris"))
}

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script, Video};
    match route.header.get(..4) {
        Some(b"YCG\0") => Some(Image("ycg/yuris")),
        Some(b"YSMV") => Some(Video("ymv/yuris")),
        Some(b"YSTB" | b"YSCM" | b"YSCF" | b"YSER" | b"YSLB" | b"YSTD" | b"YSTL" | b"YSVR") => {
            Some(Script("ybn/yuris"))
        }
        _ => None,
    }
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    (route.ext == "ypf").then(|| route.archive_with("ypf/yuris"))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script, Video};
    match route.ext {
        "ycg" => Some(Image("ycg/yuris")),
        "ybn" => Some(Script("ybn/yuris")),
        "ymv" => Some(Video("ymv/yuris")),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/yuris/route.rs"]
mod tests;
