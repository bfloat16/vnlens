//! Escu:de host source archive path resolution.
use crate::context::Context;
use nvlens_core::{ArchiveOptions, Error, Result};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

pub(super) fn resolve(
    context: &Context,
    paths: &[PathBuf],
    cancelled: &AtomicBool,
) -> Result<ArchiveOptions> {
    let mut options = ArchiveOptions::default();
    // WinMain's default source root is the executable basename; OpenFastFile
    // resolves its first path component to the same-named .bin archive.
    for path in paths {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
        {
            let view = context.files.open(path)?;
            let Some(image) = context.image(&view, cancelled)? else {
                continue;
            };
            if !super::pe(&image)? {
                continue;
            }
            let source = path.with_extension("bin");
            if let Some(previous) = options.paths.insert("escude_source", source.clone())
                && previous != source
            {
                return Err(Error::Unsupported("Multiple Escu:de source hosts".into()));
            }
        }
    }
    Ok(options)
}
