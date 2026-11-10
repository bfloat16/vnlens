//! YU-RIS loader strings and relocated x86 key initialization (0x46327C).
mod key;
mod route;

use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::Result;
use nvlens_io::pe::PeImage;

fn pe(pe: &PeImage<'_>) -> Result<bool> {
    Ok(has(pe, b"ysbin\\yst%05d.ybn")? && has(pe, b"ysbin\\yst_list.ybn")?)
}

fn layout(context: &crate::context::Context) -> bool {
    context.files.is_file(&context.root.join("pac/Scripts.ypf"))
        && context
            .files
            .is_file(&context.root.join("pac/Graphics.ypf"))
}

nvlens_core::inventory::submit! {
    Detector {
        engine: Engine::Yuris,
        supersedes: None,
        subdirs: &["pac"],
        pe,
        layout,
        resolve: key::resolve,
        route: route::ROUTER,
    }
}
