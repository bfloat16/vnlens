//! AdvHD v2: PE product strings; packed executables use the launcher/archive layout.
use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::Result;
use nvlens_io::pe::PeImage;
mod ws2;
fn pe(pe: &PeImage<'_>) -> Result<bool> {
    Ok(has(pe, b"AdvHD")? && has(pe, b"WillPlus")?)
}
fn layout(root: &std::path::Path) -> bool {
    root.join("AdvHD.exe").is_file()
        && root.join("Script2.arc").is_file()
        && root.join("Graphic.arc").is_file()
}
fn resolve(
    _: &std::path::Path,
    paths: &[std::path::PathBuf],
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<nvlens_core::ArchiveOptions> {
    let mut options = nvlens_core::ArchiveOptions::default();
    for path in paths {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(nvlens_core::Error::Cancelled);
        }
        let view = nvlens_io::ArcView::open(path)?;
        let Some(image) = PeImage::parse(view.slice(0, view.len())?).ok().flatten() else {
            continue;
        };
        if let Some(table) = ws2::table(&image, cancel)? {
            let key = nvlens_core::Secret::new(table);
            if options.keys.get("will_ws2").is_some_and(|old| old != &key) {
                return Err(nvlens_core::Error::UnknownScheme(Some(
                    "Conflicting AdvHD WS2 layouts".into(),
                )));
            }
            options.keys.insert("will_ws2", key);
        }
    }
    Ok(options)
}
nvlens_core::inventory::submit! { Detector { pe, layout, engine: Engine::Will, resolve } }
