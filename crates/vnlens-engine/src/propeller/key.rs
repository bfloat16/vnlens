//! Propeller Stuff version and XOR parameter resolution.
use crate::{context::Context, detect::has};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_core::{ArchiveOptions, Error, Result, Secret};

pub(super) fn resolve(
    context: &Context,
    paths: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<ArchiveOptions> {
    let mut version = None;
    for path in paths {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let view = context.files.open(path)?;
        let Some(image) = context.image(&view, cancel)? else {
            continue;
        };
        if !super::pe(&image)? {
            continue;
        }
        let candidate = match (
            has(&image, b"Stuff v1.0a\0")?,
            has(&image, b"Stuff v1.4\0")?,
        ) {
            (true, false) => 10,
            (false, true) => 14,
            _ => {
                return Err(Error::UnknownScheme(Some(
                    "Unknown or conflicting Propeller Stuff version".into(),
                )));
            }
        };
        if version.is_some_and(|old| old != candidate) {
            return Err(Error::UnknownScheme(Some(
                "Conflicting Propeller Stuff versions".into(),
            )));
        }
        version = Some(candidate);
    }
    let version = version.ok_or_else(|| {
        Error::UnknownScheme(Some("Missing Propeller Stuff version evidence".into()))
    })?;
    let mut options = ArchiveOptions::default();
    options
        .keys
        .insert("propeller_mpk", Secret::new(vec![0x58]));
    options.keys.insert(
        "propeller_msc",
        Secret::new(vec![if version == 14 { 0x77 } else { 0x88 }]),
    );
    options.numbers.insert("propeller_msc_version", version);
    Ok(options)
}
