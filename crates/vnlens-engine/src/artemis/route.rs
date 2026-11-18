//! Native PFS names, source scripts and serialized ASB command blocks.
use crate::routing::{Route, Router};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use vnlens_core::{ArchiveRoute, ResourceOrigin, ResourceRoute};

pub(super) const ROUTER: Router = Router {
    // CArtemisParser::load accepts ASB records under the .iet source name.
    header_first: &["iet"],
    archive,
    extension,
    header,
    archive_set,
    ..Router::NONE
};

fn pfs_name(name: &str) -> bool {
    name.ends_with(".pfs")
        || name.rsplit_once('.').is_some_and(|(base, part)| {
            base.ends_with(".pfs") && part.len() == 3 && part.bytes().all(|b| b.is_ascii_digit())
        })
}

fn archive(route: &Route<'_>) -> Option<ArchiveRoute> {
    if !pfs_name(route.leaf) {
        return None;
    }
    let mut archive = route.archive_with("pfs/artemis");
    if route.origin == ResourceOrigin::File {
        archive.options.numbers.insert("artemis_companions", 1);
    }
    Some(archive)
}

fn extension(route: &Route<'_>) -> Option<ResourceRoute> {
    match route.ext {
        "ast" | "ipt" | "tbl" => Some(ResourceRoute::Script("lua")),
        "iet" | "ini" | "sli" => Some(ResourceRoute::Script("text/artemis")),
        "asb" => Some(ResourceRoute::Script("asb/artemis")),
        _ => None,
    }
}

fn header(route: &Route<'_>) -> Option<ResourceRoute> {
    if route.header.starts_with(b"pf8") {
        Some(ResourceRoute::Archive(Box::new(
            route.archive_with("pfs/artemis"),
        )))
    } else if route.header.starts_with(b"ASB") {
        Some(ResourceRoute::Script("asb/artemis"))
    } else {
        None
    }
}

fn archive_set(
    name: &str,
    primary: &Path,
    names: &BTreeMap<String, &PathBuf>,
) -> Option<(PathBuf, Vec<String>)> {
    if !name.ends_with(".pfs") {
        return None;
    }
    let mut members = vec![name.to_owned()];
    members.extend(
        names
            .keys()
            .filter(|candidate| {
                candidate.strip_prefix(name).is_some_and(|suffix| {
                    suffix.len() == 4
                        && suffix.starts_with('.')
                        && suffix[1..].bytes().all(|b| b.is_ascii_digit())
                })
            })
            .cloned(),
    );
    Some((primary.to_path_buf(), members))
}
