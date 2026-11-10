//! Softpal's PAL host identifies itself through its imported PAL API and
//! Script.src / Point.dat resource names; PAC content is not identification evidence.
mod route;

use crate::{
    Engine,
    detect::{Detector, has, plain},
};
use nvlens_core::Result;
use nvlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"PalFileCreate")? && has(image, b"Script.src")? && has(image, b"Point.dat")?)
}

fn layout(context: &crate::context::Context) -> bool {
    context.files.is_file(&context.root.join("dll/Pal.dll"))
        && context.files.is_file(&context.root.join("data.pac"))
        && context.files.is_file(&context.root.join("system.pac"))
}

nvlens_core::inventory::submit! {
    Detector {
        engine: Engine::Softpal,
        supersedes: None,
        subdirs: &["dll", "pac"],
        pe,
        layout,
        resolve: plain,
        route: route::ROUTER,
    }
}
