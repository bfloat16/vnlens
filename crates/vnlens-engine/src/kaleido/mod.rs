//! Kaleido ADV Workshop's M2/ADVENGINE host. PE source/VM markers identify the
//! host; decoded startup instructions supply the filename cipher parameters.
mod key;
mod route;

use crate::{
    Engine,
    detect::{Detector, has, unscoped},
};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

pub(super) fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"advengine/src/")?
        && has(image, b"script/main.nut")?
        && has(image, b"Squirrel 2.2.4")?
        && has(image, b"M2LIB_SPEC=")?)
}

fn layout(context: &crate::context::Context) -> bool {
    let data = context.root.join("wind3d11data");
    context.files.is_file(&data.join("script_info.psb.m"))
        && context.files.is_file(&data.join("scenario_info.psb.m"))
        && context.files.is_file(&data.join("script_body.bin"))
        && context.files.is_file(&data.join("scenario_body.bin"))
}

vnlens_core::inventory::submit! {
    Detector {
        engine: Engine::Kaleido,
        supersedes: None,
        subdirs: &["wind3d11data/movie", "wind3d11data"],
        pe,
        layout,
        resolve: key::resolve,
        scope: unscoped,
        route: route::ROUTER,
    }
}
