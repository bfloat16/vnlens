//! AGES-MK2 archive routing and per-archive scramble key selection.
use crate::routing::{Route, Router};
use vnlens_core::{ArchiveRoute, ResourceRoute};

pub(super) const ROUTER: Router = Router {
    header,
    archive,
    ..Router::NONE
};

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    route
        .header
        .starts_with(b"FPD\0")
        .then(|| fpd(route))
        .flatten()
        .map(|route| ResourceRoute::Archive(Box::new(route)))
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    matches!(route.ext, "fpd" | "dat")
        .then(|| fpd(route))
        .flatten()
}

fn fpd(route: &Route<'_>) -> Option<ArchiveRoute> {
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
