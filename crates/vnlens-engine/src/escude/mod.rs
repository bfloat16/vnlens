//! Escu:de host identity from its window classes, mutex and archive reader.
//! The identifiers occur together in WinMain and OpenFastFile; archive bytes
//! and the executable's filename are not identification evidence.
mod key;
mod route;

use crate::{
    Engine,
    detect::{Detector, has},
};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

pub(super) fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"ESCUDE_GAMES_VIEW")?
        && has(image, b"ESCUDE_GAMES_FRAME")?
        && has(image, b"ESCUDE_GAMES_MUTEX")?
        && has(image, b"ESC-ARC")?)
}

fn layout(_context: &crate::context::Context) -> bool {
    false
}

vnlens_core::inventory::submit! {
    Detector {
        engine: Engine::Escude,
        supersedes: None,
        subdirs: &[],
        pe,
        layout,
        resolve: key::resolve,
        route: route::ROUTER,
    }
}
