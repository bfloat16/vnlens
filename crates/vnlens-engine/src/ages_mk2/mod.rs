//! smash::fw PackFile fingerprints and verified GetPackSolt() parameters.
mod key;
mod route;

use crate::{
    Engine,
    detect::{Detector, has, unscoped},
};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

fn pe(pe: &PeImage<'_>) -> Result<bool> {
    Ok(has(pe, b"smash")? && has(pe, b"PackFile")?)
}

fn layout(_context: &crate::context::Context) -> bool {
    false
}

vnlens_core::inventory::submit! {
    Detector {
        engine: Engine::AgesMk2,
        supersedes: None,
        subdirs: &[],
        pe,
        layout,
        resolve: key::resolve,
        scope: unscoped,
        route: route::ROUTER,
    }
}
