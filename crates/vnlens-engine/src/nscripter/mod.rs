//! Classic NScripter: the version banner, script loader and NSA startup paths.
//! Verified in NScripter 2.82, sub_40D780 and sub_4466D0. No archive payload
//! is read to identify the engine or classify its resources.
mod route;

use crate::{
    Engine,
    detect::{Detector, has, plain, unscoped},
};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"NScripter Version ")?
        && has(image, b"nscript.dat\0")?
        && has(image, b"arc%d.nsa\0")?)
}

vnlens_core::inventory::submit! {
    Detector {
        file: crate::detect::no_container,
        engine: Engine::NScripter,
        supersedes: None,
        subdirs: &[],
        pe,
        layout: |_| false,
        resolve: plain,
        scope: unscoped,
        route: route::ROUTER,
    }
}

#[cfg(test)]
#[path = "../../tests/nscripter/mod.rs"]
mod tests;
