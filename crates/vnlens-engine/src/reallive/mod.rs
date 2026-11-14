//! RealLive identity: its save-data marker and SEEN storage implementation.
mod key;
mod route;

use crate::{
    Engine,
    detect::{Detector, has, unscoped},
};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"RealLive SAVEDATA")? && has(image, b"SEEN.TXT")?)
}

fn layout(context: &crate::context::Context) -> bool {
    context.files.is_file(&context.root.join("Gameexe.ini"))
        && context.files.is_file(&context.root.join("Seen.txt"))
        && context.files.is_dir(&context.root.join("g00"))
        && context.files.is_dir(&context.root.join("koe"))
}

vnlens_core::inventory::submit! {
    Detector {
        file: crate::detect::no_container,
        engine: Engine::RealLive,
        supersedes: None,
        subdirs: &["g00", "pdt", "gan", "bgm", "wav", "koe", "mov", "seen"],
        pe,
        layout,
        resolve: key::resolve,
        scope: unscoped,
        route: route::ROUTER,
    }
}
