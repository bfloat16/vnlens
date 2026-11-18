//! Artemis Rev.3257 identifies itself in its version banner and pack-file
//! loader. CArtemisPackFile/CPackFile::open (sub_1401884A0) loads independent
//! numbered .pfs companions. Identification never reads their indices.
mod route;

use crate::{
    Engine,
    detect::{Detector, has, plain, unscoped},
};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"Artemis Engine Rev.")? && has(image, b"\\root.pfs\0")?)
}

vnlens_core::inventory::submit! {
    Detector {
        engine: Engine::Artemis,
        supersedes: None,
        subdirs: &["movie", "script", "system", "image", "sound"],
        pe,
        layout: |_| false,
        file: crate::detect::no_container,
        resolve: plain,
        scope: unscoped,
        route: route::ROUTER,
    }
}

#[cfg(test)]
#[path = "../../tests/artemis/mod.rs"]
mod tests;
