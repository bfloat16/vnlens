//! AdvHD v2: PE product strings; packed executables use the launcher/archive layout.
mod key;
mod route;

use crate::{
    Engine,
    detect::{Detector, has, unscoped},
};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

fn pe(pe: &PeImage<'_>) -> Result<bool> {
    Ok(has(pe, b"AdvHD")? && has(pe, b"WillPlus")?)
}

fn layout(context: &crate::context::Context) -> bool {
    context.files.is_file(&context.root.join("AdvHD.exe"))
        && context.files.is_file(&context.root.join("Script2.arc"))
        && context.files.is_file(&context.root.join("Graphic.arc"))
}

vnlens_core::inventory::submit! {
    Detector {
        file: crate::detect::no_container,
        engine: Engine::Will,
        supersedes: None,
        subdirs: &[],
        pe,
        layout,
        resolve: key::resolve,
        scope: unscoped,
        route: route::ROUTER,
    }
}

#[cfg(test)]
#[path = "../../tests/will/mod.rs"]
mod tests;
