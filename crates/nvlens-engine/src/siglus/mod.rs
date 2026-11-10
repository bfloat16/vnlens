//! SiglusEngine PE identity and static resource-key recovery.
mod key;
mod route;

use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::Result;
use nvlens_io::pe::PeImage;

pub(super) fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"SiglusEngine")? && has(image, b"Scene.pck")? && has(image, b"Gameexe.dat")?)
}

fn layout(context: &crate::context::Context) -> bool {
    context.files.is_file(&context.root.join("Scene.pck"))
        && context.files.is_file(&context.root.join("Gameexe.dat"))
        && context.files.is_dir(&context.root.join("g00"))
        && context.files.is_dir(&context.root.join("koe"))
}

nvlens_core::inventory::submit! {
    Detector {
        engine: Engine::Siglus,
        supersedes: None,
        subdirs: &["g00", "gan", "bgm", "wav", "koe", "mov"],
        pe,
        layout,
        resolve: key::resolve,
        route: route::ROUTER,
    }
}
