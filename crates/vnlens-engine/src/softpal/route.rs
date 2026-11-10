//! Softpal resource and PAC archive routing.
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
    (route.ext == "tga").then_some(ResourceRoute::Image("tga"))
}

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script};
    let bytes = route.header;
    if bytes.starts_with(b"GE ") || bytes.starts_with(b"PGD3") {
        Some(Image("pgd/softpal"))
    } else if bytes.starts_with(b"Sv20")
        || bytes.starts_with(b"$TEXT_LIST_")
        || bytes.starts_with(b"$FILE_LIST_")
        || bytes.starts_with(b"$POINT_LIST_")
        || bytes.starts_with(b"$MEM_LIST_")
        || bytes.starts_with(b"$GRAPH_LIST_")
    {
        Some(Script("script/softpal"))
    } else {
        None
    }
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    (route.ext == "pac").then(|| route.archive_with("pac/softpal"))
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    use ResourceRoute::{Image, Script};
    match route.ext {
        "pgd" => Some(Image("pgd/softpal")),
        "src" | "csv" | "txt" | "ini" => Some(Script("script/softpal")),
        "dat"
            if matches!(
                route.leaf,
                "text.dat" | "file.dat" | "point.dat" | "mem.dat" | "graphic.dat" | "archive.dat"
            ) =>
        {
            Some(Script("script/softpal"))
        }
        _ => None,
    }
}
