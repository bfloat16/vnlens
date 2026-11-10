//! KiriKiri Z Hxv4 identity and static bootstrap parameter recovery.
mod key;
mod route;

use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::Result;
use nvlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(
        (has(image, b"Hxv4")? && has(image, b"PARAMS")? && has(image, b"FilterManager")?)
            || (image.resource("#10", "STARTUP.TJS")?.is_some()
                && image.resource("#10", "BOOTSTRAP")?.is_some()
                && image.resource("TEXT", "#127")?.is_some()),
    )
}

fn layout(_context: &crate::context::Context) -> bool {
    false
}

nvlens_core::inventory::submit! {
    Detector {
        engine: Engine::KrkrzHxv4,
        supersedes: Some(Engine::Krkr),
        subdirs: &[],
        pe,
        layout,
        resolve: key::resolve,
        route: route::ROUTER,
    }
}
