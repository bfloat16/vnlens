//! KiriKiri host identity and XP3 extraction-filter selection. PE plugin
//! exports and decoded registration/callback instructions establish the
//! algorithm; archive contents, plugin filenames and game titles are unused.
mod tpm;
use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::{ArchiveOptions, Error, Result};
use nvlens_io::{ArcView, pe::PeImage};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"TVP(KIRIKIRI)")? && has(image, b"tTVPXP3Archive")?)
}
fn layout(_: &Path) -> bool {
    false
}
fn resolve(_: &Path, paths: &[PathBuf], cancel: &AtomicBool) -> Result<ArchiveOptions> {
    let mut options = ArchiveOptions::default();
    for path in paths {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let view = ArcView::open(path)?;
        let Some(mut image) = PeImage::parse(view.slice(0, view.len())?)? else {
            continue;
        };
        nvlens_unpack::steamstub::unpack(&mut image, cancel)?;
        if tpm::xor31(&image)? {
            options.numbers.insert("xp3_xor31", 1);
        }
    }
    Ok(options)
}
nvlens_core::inventory::submit! { Detector { pe, layout, engine: Engine::Krkr, resolve } }
