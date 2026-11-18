//! Tamlib PC identification from independent texture-runtime diagnostics.
//! ToHeart's CAT accessors are sub_140592220/250/2C0/430/510; its DDS array
//! consumer is Tamlib::DataTexture::Impl::construct (sub_14059B160).
mod route;

use crate::{
    Engine,
    detect::{Detector, has, plain, unscoped},
};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"Tamlib::DataTexture::Impl::construct\0")?
        && has(image, b"Tamlib::TamTexture::Impl::construct\0")?)
}

vnlens_core::inventory::submit! {
    Detector {
        engine: Engine::Tamsoft,
        supersedes: None,
        subdirs: &["ui", "model", "sound", "movie", "binary", "effect", "posteffect", "tam_sys", "system", "graphics", "motion", "addcontents"],
        pe,
        layout: |_| false,
        file: crate::detect::no_container,
        resolve: plain,
        scope: unscoped,
        route: route::ROUTER,
    }
}

#[cfg(test)]
#[path = "../../tests/tamsoft/mod.rs"]
mod tests;
