//! Native container framing and static TMD0 models are classified; scripts,
//! motion and material records have no decoder route. Unknown suffixes stay unknown.
use crate::routing::{Route, Router};
use vnlens_core::{ArchiveRoute, ResourceKind, ResourceRoute};
use vnlens_io::BinaryReader;

pub(super) const ROUTER: Router = Router {
    archive,
    header,
    extension,
    ..Router::NONE
};

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    if script_bank(route) {
        return None;
    }
    Some(route.archive_with(match route.ext {
        "cat" => "cat/tamsoft",
        "semb" => "semb/tamsoft",
        _ => return None,
    }))
}

// ToHeart's AdvScriptPack banks live in Binary/Adv (also under AddContents).
// They remain whole files while script disassembly is outside this adaptation.
fn script_bank(route: &Route<'_>) -> bool {
    route.ext == "cat"
        && (route.name.starts_with("binary/adv/") || route.name.contains("/binary/adv/"))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    if route.ext == "tmd" {
        return Some(ResourceRoute::Model("tmd/tamsoft"));
    }
    script_bank(route).then_some(ResourceRoute::Other(ResourceKind::Script))
}

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    let h = route.header;
    if h.starts_with(b"tmd0") {
        return Some(ResourceRoute::Model("tmd/tamsoft"));
    }
    let tag = if h.starts_with(b"EMOJIPCK") {
        "semb/tamsoft"
    } else if h.len() >= 16 {
        let flags = BinaryReader::u32_le(h);
        let count = u64::from(BinaryReader::u32_le(&h[4..]));
        // The identified PC runtime emits LE CATs. Version-2 mesh records
        // are not BE CATs and must retain their raw route.
        if matches!(flags, 1 | 3)
            && BinaryReader::u32_le(&h[8..]) == 0
            && count != 0
            && u64::from(BinaryReader::u32_le(&h[12..])) >= 12 + count * 12
        {
            "cat/tamsoft"
        } else if u64::from(BinaryReader::u32_le(h))
            == 12 + u64::from(BinaryReader::u32_le(&h[4..])) * 4
            && BinaryReader::u32_le(&h[4..]) != 0
            && BinaryReader::u32_le(&h[12..]) == 0
            && u64::from(BinaryReader::u32_le(&h[8..])) >= 12 + count * (4 + 128)
            && (u64::from(flags) + 4 > h.len() as u64
                || h.get(flags as usize..flags as usize + 4) == Some(b"DDS "))
        {
            "textures/tamsoft"
        } else {
            return None;
        }
    } else {
        return None;
    };
    Some(ResourceRoute::Archive(Box::new(route.archive_with(tag))))
}
