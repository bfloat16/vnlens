//! BGI/Ethornell resource and archive routing.
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
    use ResourceRoute::{Audio, Image, Script};
    let bytes = route.header;
    if bytes.starts_with(b"BURIKO ARC20") || bytes.starts_with(b"PackFile    ") {
        return Some(ResourceRoute::Archive(Box::new(
            route.archive_with("arc/bgi"),
        )));
    }
    if bytes.starts_with(b"CompressedBG___\0") || bitmap(bytes) {
        Some(Image("image/bgi"))
    } else if matches!(bytes.get(4..8), Some(b"bw  " | b"hw  ")) {
        Some(Audio("bw/bgi"))
    } else if bytes.starts_with(b"BurikoCompiledScriptVer1.00\0")
        || (bytes.starts_with(b"\x10\0\0\0") && bytes.get(8..16) == Some(&[0; 8]))
    {
        Some(Script("script/bgi"))
    } else {
        None
    }
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    (route.ext == "arc").then(|| route.archive_with("arc/bgi"))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Audio, Image, Script};
    match route.ext {
        "bgi" | "bg" | "_bg" => Some(Image("image/bgi")),
        "bw" | "hw" | "_bw" => Some(Audio("bw/bgi")),
        "_bp" | "bss" => Some(Script("script/bgi")),
        _ => None,
    }
}

// Raw BGI bitmaps have no magic. These fixed header fields distinguish their
// engine-local route; the image reader validates dimensions against the payload.
fn bitmap(bytes: &[u8]) -> bool {
    bytes.len() >= 16
        && BinaryReader::u16_le(bytes) != 0
        && BinaryReader::u16_le(&bytes[2..]) != 0
        && matches!(BinaryReader::u16_le(&bytes[4..]), 8 | 24 | 32)
        && BinaryReader::u16_le(&bytes[6..]) <= 1
        && bytes[8..16] == [0; 8]
}

#[cfg(test)]
#[path = "../../tests/bgi/route.rs"]
mod tests;
