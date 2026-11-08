//! SiglusEngine PE identity and static resource-key recovery.
mod key;
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
    Ok(has(image, b"SiglusEngine")? && has(image, b"Scene.pck")? && has(image, b"Gameexe.dat")?)
}
fn layout(root: &Path) -> bool {
    root.join("Scene.pck").is_file()
        && root.join("Gameexe.dat").is_file()
        && root.join("g00").is_dir()
        && root.join("koe").is_dir()
}
fn missing() -> Error {
    Error::UnknownScheme(Some(
        "Siglus resource-key code features were not resolved".into(),
    ))
}

fn resolve(_: &Path, executables: &[PathBuf], cancelled: &AtomicBool) -> Result<ArchiveOptions> {
    let mut result = None;
    for executable in executables {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let view = ArcView::open(executable)?;
        let Some(image) = PeImage::parse(view.slice(0, view.len())?).ok().flatten() else {
            continue;
        };
        if !pe(&image)? {
            continue;
        }
        let options = key::parameters(&image, cancelled)?;
        if result.as_ref().is_some_and(|previous| previous != &options) {
            return Err(Error::UnknownScheme(Some(
                "Conflicting Siglus executable parameters".into(),
            )));
        }
        result = Some(options);
    }
    result.ok_or_else(missing)
}

nvlens_core::inventory::submit! { Detector { pe, layout, engine: Engine::Siglus, resolve } }
