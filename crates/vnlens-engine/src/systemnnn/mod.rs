//! NNNCommonGame / SystemNNN host identification. Resource paths are the
//! conventions used by NNNLib, not evidence obtained from archive contents.
mod route;

use crate::{
    Engine,
    detect::{Detector, has, plain, unscoped},
};
use vnlens_core::Result;
use vnlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"NNNCommonGameByTinyan")?
        && has(image, b"NNNUtilLib :")?
        && has(image, b"NNNLib :")?)
}

fn layout(_context: &crate::context::Context) -> bool {
    false
}

vnlens_core::inventory::submit! {
    Detector {
        engine: Engine::SystemNnn,
        supersedes: None,
        subdirs: &["dwq", "cdvaw", "vaw", "wgq", "spt", "init2", "nya"],
        pe,
        layout,
        resolve: plain,
        scope: unscoped,
        route: route::ROUTER,
    }
}
