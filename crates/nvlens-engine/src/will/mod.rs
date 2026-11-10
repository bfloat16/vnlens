//! AdvHD v2: PE product strings; packed executables use the launcher/archive layout.
mod key;
mod route;

use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::Result;
use nvlens_io::pe::PeImage;

fn pe(pe: &PeImage<'_>) -> Result<bool> {
    Ok(has(pe, b"AdvHD")? && has(pe, b"WillPlus")?)
}

fn layout(context: &crate::context::Context) -> bool {
    context.files.is_file(&context.root.join("AdvHD.exe"))
        && context.files.is_file(&context.root.join("Script2.arc"))
        && context.files.is_file(&context.root.join("Graphic.arc"))
}

nvlens_core::inventory::submit! {
    Detector {
        engine: Engine::Will,
        supersedes: None,
        subdirs: &[],
        pe,
        layout,
        resolve: key::resolve,
        route: route::ROUTER,
    }
}
