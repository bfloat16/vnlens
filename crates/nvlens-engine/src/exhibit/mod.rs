//! ExHIBIT / RetouchSystem host identification.
mod key;
mod route;

use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::Result;
use nvlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"ExHIBIT.ini")?
        && (has(image, b"RetouchSendExHIBIT")? || has(image, b"RetouchSystem@@")?))
}

fn layout(context: &crate::context::Context) -> bool {
    context.files.is_file(&context.root.join("ExHIBIT.ini"))
        && context.files.is_file(&context.root.join("resident.dll"))
        && context.files.is_dir(&context.root.join("rld"))
        && context.files.is_dir(&context.root.join("res"))
}

nvlens_core::inventory::submit! {
    Detector {
        engine: Engine::Exhibit,
        supersedes: None,
        subdirs: &["res", "rld", "dat"],
        pe,
        layout,
        resolve: key::resolve,
        route: route::ROUTER,
    }
}
