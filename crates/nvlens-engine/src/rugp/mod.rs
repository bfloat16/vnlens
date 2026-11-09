//! rUGP identity from the serialization host's runtime classes. These coexist
//! in UnivUI.dll across the verified 2008-2011 releases. No RIO is inspected
//! to identify a game, and the executable/plugin filename is not evidence.
mod schema;
use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::Result;
use nvlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"CObjectArcMan")?
        && has(image, b"CPmArchiveWay")?
        && has(image, b"CVmVarObj")?
        && has(image, b"CStdb")?)
}
nvlens_core::inventory::submit! {
    Detector { pe, layout: |_| false, engine: Engine::Rugp, resolve: schema::resolve }
}
