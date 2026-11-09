//! Propeller's Stuff v1.0a host: WinMain's class name and MSC startup paths.
//! sub_406490 and sub_406700 use separate MPK-index and MSC XOR constants.
use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::{ArchiveOptions, Result, Secret};
use nvlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"Stuff v1.0a")?
        && has(image, b"system_edit.msc")?
        && has(image, b"Scenario\\system.msc")?
        && has(image, b"Scenario.mpk")?)
}

fn resolve(
    _: &std::path::Path,
    _: &[std::path::PathBuf],
    _: &std::sync::atomic::AtomicBool,
) -> Result<ArchiveOptions> {
    let mut options = ArchiveOptions::default();
    options
        .keys
        .insert("propeller_mpk", Secret::new(vec![0x58]));
    options
        .keys
        .insert("propeller_msc", Secret::new(vec![0x88]));
    Ok(options)
}

nvlens_core::inventory::submit! {
    Detector { pe, layout: |_| false, engine: Engine::Propeller, resolve }
}
