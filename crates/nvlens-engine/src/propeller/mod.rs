//! Propeller Stuff: WinMain's versioned class name and MSC startup paths.
//! v1.0a sub_406490/sub_406700 and v1.4 sub_45BCC0/sub_45BA40 use the
//! same MPK index layout but different MSC XOR constants and integer widths.
mod key;
mod route;

use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::Result;
use nvlens_io::pe::PeImage;

pub(super) fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"Stuff v")?
        && has(image, b"system_edit.msc")?
        && has(image, b"Scenario\\system.msc")?
        && has(image, b"Scenario.mpk")?)
}

fn layout(_context: &crate::context::Context) -> bool {
    false
}

nvlens_core::inventory::submit! {
    Detector {
        engine: Engine::Propeller,
        supersedes: None,
        subdirs: &[],
        pe,
        layout,
        resolve: key::resolve,
        route: route::ROUTER,
    }
}
