//! NNNCommonGame / SystemNNN host identification. Resource paths are the
//! conventions used by NNNLib, not evidence obtained from archive contents.

use crate::{
    Engine,
    detect::{Detector, has, plain},
};
use nvlens_core::Result;
use nvlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"NNNCommonGameByTinyan")?
        && has(image, b"NNNUtilLib :")?
        && has(image, b"NNNLib :")?)
}

nvlens_core::inventory::submit! {
    Detector { pe, layout: |_| false, engine: Engine::SystemNnn, resolve: plain }
}
