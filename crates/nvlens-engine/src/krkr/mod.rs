//! KiriKiri host identity and XP3 extraction-filter selection. PE plugin
//! exports and decoded registration/callback instructions establish the
//! algorithm; archive contents, plugin filenames and game titles are unused.
mod key;
pub(crate) mod route;

use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::Result;
use nvlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"TVP(KIRIKIRI)")? && has(image, b"tTVPXP3Archive")?)
}

fn layout(_context: &crate::context::Context) -> bool {
    false
}

nvlens_core::inventory::submit! {
    Detector {
        engine: Engine::Krkr,
        supersedes: None,
        subdirs: &[],
        pe,
        layout,
        resolve: key::resolve,
        route: route::ROUTER,
    }
}
