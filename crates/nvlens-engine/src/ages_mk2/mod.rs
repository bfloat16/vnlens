//! smash::fw PackFile fingerprints and verified GetPackSolt() parameters.
mod key;
mod route;

use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::Result;
use nvlens_io::pe::PeImage;

fn pe(pe: &PeImage<'_>) -> Result<bool> {
    Ok(has(pe, b"smash")? && has(pe, b"PackFile")?)
}

fn layout(_context: &crate::context::Context) -> bool {
    false
}

nvlens_core::inventory::submit! {
    Detector {
        engine: Engine::AgesMk2,
        supersedes: None,
        subdirs: &[],
        pe,
        layout,
        resolve: key::resolve,
        route: route::ROUTER,
    }
}
