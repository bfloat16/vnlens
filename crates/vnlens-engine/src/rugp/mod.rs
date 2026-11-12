//! rUGP identity from the serialization host's runtime classes. These coexist
//! in UnivUI.dll across the verified 2008-2011 releases. No RIO is inspected
//! to identify a game, and the executable/plugin filename is not evidence.
mod key;
mod route;

use crate::{
    Engine,
    detect::{Detector, has, unscoped},
};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"CObjectArcMan")?
        && has(image, b"CPmArchiveWay")?
        && has(image, b"CVmVarObj")?
        && has(image, b"CStdb")?)
}

fn layout(_context: &crate::context::Context) -> bool {
    false
}

vnlens_core::inventory::submit! {
    Detector {
        engine: Engine::Rugp,
        supersedes: None,
        subdirs: &[],
        pe,
        layout,
        resolve: key::resolve,
        scope: unscoped,
        route: route::ROUTER,
    }
}
