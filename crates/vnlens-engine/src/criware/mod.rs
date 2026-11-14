//! CRIWARE middleware identity and directed routes. A host's PE imports or
//! explicit bank/container names supply evidence; no game engine is guessed.
use crate::{
    context::Context,
    detect::{Middleware, has},
    routing::{Route, Router},
};
use vnlens_core::{ArchiveRoute, ResourceRoute, Result};
use vnlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"CRIWARE")?
        || has(image, b"criAtomEx")?
        || has(image, b"criManaPlayer")?
        || has(image, b"criFsBinder")?)
}
fn layout(context: &Context) -> bool {
    context.files.read_dir(&context.root).is_ok_and(|entries| {
        entries.iter().any(|entry| {
            entry
                .path
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|ext| {
                    matches!(
                        ext.to_ascii_lowercase().as_str(),
                        "cpk" | "acb" | "awb" | "usm"
                    )
                })
        })
    })
}
const ROUTER: Router = Router {
    header,
    archive,
    extension,
    ..Router::NONE
};

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    let tag = if route.header.starts_with(b"CPK ") {
        "cri/cpk"
    } else if route.header.starts_with(b"AFS2") {
        "cri/awb"
    } else if route.header.starts_with(b"@UTF")
        || route.header.starts_with(&[0x1f, 0x9e, 0xf3, 0xf5])
    {
        "cri/utf"
    } else if route.header.starts_with(b"CRID") {
        return Some(ResourceRoute::Video("cri/usm"));
    } else if route.header.len() >= 4
        && route.header[..4]
            .iter()
            .map(|v| v & 0x7f)
            .eq(b"HCA\0".iter().copied())
    {
        return Some(ResourceRoute::Audio("cri/hca"));
    } else if route.header.starts_with(&[0x80, 0])
        && route.header.get(4).is_some_and(|v| (2..=5).contains(v))
    {
        return Some(ResourceRoute::Audio("cri/adx"));
    } else {
        return None;
    };
    Some(ResourceRoute::Archive(Box::new(route.archive_with(tag))))
}
fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    let tag = match route.ext {
        "cpk" | "pck" => "cri/cpk",
        "acb" => "cri/acb",
        "awb" | "afs2" => "cri/awb",
        "utf" => "cri/utf",
        _ => return None,
    };
    Some(route.archive_with(tag))
}
fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    match route.ext {
        "usm" => Some(ResourceRoute::Video("cri/usm")),
        "hca" => Some(ResourceRoute::Audio("cri/hca")),
        "adx" => Some(ResourceRoute::Audio("cri/adx")),
        _ => None,
    }
}
vnlens_core::inventory::submit! { Middleware { subdirs: &[], pe, layout, route: ROUTER } }

#[cfg(test)]
#[path = "../../tests/criware/mod.rs"]
mod tests;
