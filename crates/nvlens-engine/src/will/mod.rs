//! AdvHD v2: PE product strings; packed executables use the launcher/archive layout.
use crate::{
    Engine,
    detect::{Detector, has, plain},
};
use nvlens_core::Result;
use nvlens_io::pe::PeImage;
fn pe(pe: &PeImage<'_>) -> Result<bool> {
    Ok(has(pe, b"AdvHD")? && has(pe, b"WillPlus")?)
}
fn layout(root: &std::path::Path) -> bool {
    root.join("AdvHD.exe").is_file()
        && root.join("Script2.arc").is_file()
        && root.join("Graphic.arc").is_file()
}
nvlens_core::inventory::submit! { Detector { pe, layout, engine: Engine::Will, resolve: plain } }
