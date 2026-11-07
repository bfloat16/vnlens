//! YU-RIS loader strings and relocated x86 key initialization (0x46327C).
mod key;
use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::{ArchiveOptions, Error, Result, Secret};
use nvlens_io::{ArcView, pe::PeImage};
use std::path::{Path, PathBuf};
fn pe(pe: &PeImage<'_>) -> Result<bool> {
    Ok(has(pe, b"ysbin\\yst%05d.ybn")? && has(pe, b"ysbin\\yst_list.ybn")?)
}
fn layout(root: &Path) -> bool {
    root.join("pac/Scripts.ypf").is_file() && root.join("pac/Graphics.ypf").is_file()
}
fn resolve(
    _: &Path,
    executables: &[PathBuf],
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<ArchiveOptions> {
    let mut found = None;
    for path in executables {
        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let view = ArcView::open(path)?;
        if let Some(key) = key::from_pe(view.slice(0, view.len())?)? {
            if found.as_ref().is_some_and(|previous| previous != &key) {
                return Err(Error::UnknownScheme(Some("Conflicting YU-RIS keys".into())));
            }
            found = Some(key);
        }
    }
    let key = found.ok_or_else(|| {
        Error::UnknownScheme(Some(
            "YU-RIS executable key initialization was not identified".into(),
        ))
    })?;
    let mut options = ArchiveOptions::default();
    options.keys.insert("ystb", key);
    // 0x45EC64 complements filename bytes; this is the verified 0x1EE profile.
    options.keys.insert("ypf_name", Secret::new(vec![0xff]));
    options.numbers.insert("version", 0x1ee);
    Ok(options)
}
nvlens_core::inventory::submit! { Detector { pe, layout, engine: Engine::Yuris, resolve } }
