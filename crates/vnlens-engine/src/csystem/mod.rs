//! Cyberworks C,system: ArchiveMap RTTI plus paired Arc and Resources filenames.
//! Earlier hosts use only Arc00..Arc10; Resources/Data%03d is a later layout.
//! The TinkerBell Ogg prefix key is the host's copyright string.
mod key;
mod route;

use crate::{
    Engine,
    detect::{Detector, has},
};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

pub(super) fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b".?AVArchiveMap@@")?
        && has(image, b"Arc00.dat")?
        && (has(image, b"Data%03d.dat")?
            || (has(image, b"Arc01.dat")?
                && has(image, b"Arc04.dat")?
                && has(image, b"Arc03.dat")?
                && has(image, b"Arc06.dat")?)))
}

fn layout(context: &crate::context::Context) -> bool {
    context.files.is_file(&context.root.join("Arc00.dat"))
        && context.files.is_file(&context.root.join("Arc01.dat"))
        && context
            .files
            .is_file(&context.root.join("Resources/Data00.dat"))
}

vnlens_core::inventory::submit! {
    Detector {
        engine: Engine::Csystem,
        supersedes: None,
        subdirs: &["resources", "movie"],
        pe,
        layout,
        resolve: key::resolve,
        route: route::ROUTER,
    }
}
