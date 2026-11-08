//! Escu:de host identity from its window classes, mutex and archive reader.
//! The identifiers occur together in WinMain and OpenFastFile; archive bytes
//! and the executable's filename are not identification evidence.
use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::Result;
use nvlens_io::pe::PeImage;

fn pe(image: &PeImage<'_>) -> Result<bool> {
    Ok(has(image, b"ESCUDE_GAMES_VIEW")?
        && has(image, b"ESCUDE_GAMES_FRAME")?
        && has(image, b"ESCUDE_GAMES_MUTEX")?
        && has(image, b"ESC-ARC")?)
}
nvlens_core::inventory::submit! {
    Detector { pe, layout: |_| false, engine: Engine::Escude, resolve }
}

fn resolve(
    _: &std::path::Path,
    paths: &[std::path::PathBuf],
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<nvlens_core::ArchiveOptions> {
    let mut options = nvlens_core::ArchiveOptions::default();
    // WinMain's default source root is the executable basename; OpenFastFile
    // resolves its first path component to the same-named .bin archive.
    for path in paths {
        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(nvlens_core::Error::Cancelled);
        }
        if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
        {
            let source = path.with_extension("bin");
            if let Some(previous) = options.paths.insert("escude_source", source.clone())
                && previous != source
            {
                return Err(nvlens_core::Error::Unsupported(
                    "Multiple Escu:de source hosts".into(),
                ));
            }
        }
    }
    Ok(options)
}
