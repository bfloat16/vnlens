//! EntisGLS resource routing. Empty headers classify only by original names;
//! the ERISA file identity at +8 and description at +16 disambiguate containers.
use crate::routing::{Route, Router};
use vnlens_core::{ArchiveRoute, ResourceRoute};
use vnlens_io::BinaryReader;

pub(super) const ROUTER: Router = Router {
    header,
    archive,
    extension,
    ..Router::NONE
};

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    let bytes = route.header;
    if (bytes.starts_with(b"Entis\x1a\0\0") || bytes.starts_with(b"VIST\x1a\0\0\0"))
        && bytes.len() >= 12
        && BinaryReader::u32_le(&bytes[8..12]) == 0x0200_0400
    {
        return Some(ResourceRoute::Archive(Box::new(
            route.archive_with("noa/entisgls"),
        )));
    }
    if bytes.starts_with(b"Entis\x1a\0\0") && bytes.len() >= 16 {
        let id = BinaryReader::u32_le(&bytes[8..12]);
        let text = &bytes[16..];
        if id == u32::MAX && text.starts_with(b"Cotopha Image file") {
            return Some(ResourceRoute::Script("csx/entisgls"));
        }
        if matches!(id, 0x0200_0100 | 0x0300_0100) {
            if text.starts_with(b"Moving Entis Image") {
                return Some(ResourceRoute::Video("mei/entisgls"));
            }
            if text.starts_with(b"Music Interleaved") {
                return Some(ResourceRoute::Audio("mio/entisgls"));
            }
            if text.starts_with(b"Entis Rasterized Image") || text.starts_with(b"EMSAC-Image") {
                return Some(ResourceRoute::Image("eri/entisgls"));
            }
        }
    }
    None
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    (route.ext == "noa").then(|| route.archive_with("noa/entisgls"))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    match route.ext {
        "eri" | "emi" => Some(ResourceRoute::Image("eri/entisgls")),
        "mio" => Some(ResourceRoute::Audio("mio/entisgls")),
        "csx" => Some(ResourceRoute::Script("csx/entisgls")),
        "mei" => Some(ResourceRoute::Video("mei/entisgls")),
        "srcxml" | "xml" | "inf" | "gds" | "txt" | "ini" => {
            Some(ResourceRoute::Script("text/entisgls"))
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/entisgls/route.rs"]
mod tests;
