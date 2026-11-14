//! Directed Otomate routes. CRI bank/audio/movie readers are shared with the
//! existing middleware implementation; CL3 members inherit this game context.
use crate::routing::{Route, Router};
use vnlens_core::{ArchiveRoute, ResourceRoute};

pub(super) const ROUTER: Router = Router {
    archive,
    extension,
    header,
    ..Router::NONE
};

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    let tag = match route.ext {
        "cl3" => "cl3/otomate",
        "cpk" => "cri/cpk",
        "acb" => "cri/acb",
        "awb" | "afs2" => "cri/awb",
        _ => return None,
    };
    Some(route.archive_with(tag))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    Some(match route.ext {
        "dat" | "stcm2" => ResourceRoute::Script("stcm2/otomate"),
        "tid" => ResourceRoute::Image("tid/otomate"),
        "hca" => ResourceRoute::Audio("cri/hca"),
        "usm" => ResourceRoute::Video("cri/usm"),
        _ => return None,
    })
}

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    let bytes = route.header;
    Some(if bytes.starts_with(b"STCM2") {
        ResourceRoute::Script("stcm2/otomate")
    } else if bytes.starts_with(b"CL3L") || bytes.starts_with(b"CL3B") {
        ResourceRoute::Archive(Box::new(route.archive_with("cl3/otomate")))
    } else if bytes.starts_with(b"TID") {
        ResourceRoute::Image("tid/otomate")
    } else if bytes.starts_with(b"CPK ") {
        ResourceRoute::Archive(Box::new(route.archive_with("cri/cpk")))
    } else if bytes.starts_with(b"AFS2") {
        ResourceRoute::Archive(Box::new(route.archive_with("cri/awb")))
    } else if bytes.starts_with(b"CRID") {
        ResourceRoute::Video("cri/usm")
    } else if bytes.len() >= 4
        && bytes[..4]
            .iter()
            .map(|v| v & 0x7f)
            .eq(b"HCA\0".iter().copied())
    {
        ResourceRoute::Audio("cri/hca")
    } else {
        return None;
    })
}
