//! AGES-MK2 archive routing and per-archive scramble key selection.
use crate::routing::{Route, Router};
use vnlens_core::ArchiveRoute;

pub(super) const ROUTER: Router = Router {
    archive,
    ..Router::NONE
};

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    if !matches!(route.ext, "fpd" | "dat") {
        return None;
    }
    let key = if route
        .name
        .split('/')
        .any(|part| part == "obb" || part.starts_with("main.") || part.starts_with("patch."))
    {
        "obb"
    } else if route.name.split('/').any(|part| {
        part == "resident" || part.starts_with("resident.") || part.starts_with("boot.")
    }) {
        "resident"
    } else if route.options.keys.len() == 1 {
        *route.options.keys.keys().next()?
    } else {
        return None;
    };
    let secret = route.options.keys.get(key)?.clone();
    let mut options = route.options.clone();
    options.keys.insert("scramble", secret);
    Some(ArchiveRoute {
        tag: "fpd",
        options,
    })
}

#[cfg(test)]
#[path = "../../tests/ages_mk2/route.rs"]
mod tests;
