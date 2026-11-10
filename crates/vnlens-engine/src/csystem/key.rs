//! C,system layout generation flag and TinkerBell audio key extraction.
use crate::{context::Context, detect::has};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_core::{ArchiveOptions, Error, Result, Secret};

pub(super) fn resolve(
    context: &Context,
    executables: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<ArchiveOptions> {
    let mut key: Option<Vec<u8>> = None;
    let mut legacy = None;
    for path in executables {
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
        let candidate = !has(&image, b"Data%03d.dat")?;
        if legacy.is_some_and(|value| value != candidate) {
            return Err(Error::UnknownScheme(Some(
                "Conflicting C,system resource layouts".into(),
            )));
        }
        legacy = Some(candidate);
        for section in &image.sections {
            let bytes = image.section_data(section)?;
            let marker = b" Copyright 2004 Cyberworks \"TinkerBell\"., all rights reserved.";
            for (at, _) in bytes
                .windows(marker.len())
                .enumerate()
                .filter(|(_, data)| *data == marker)
            {
                if at < 36 || bytes.get(at + marker.len()) != Some(&0) {
                    continue;
                }
                let candidate = &bytes[at - 36..at + marker.len()];
                if !candidate[..36].iter().enumerate().all(|(i, b)| {
                    if matches!(i, 8 | 13 | 18 | 23) {
                        *b == b'-'
                    } else {
                        b.is_ascii_hexdigit()
                    }
                }) {
                    continue;
                }
                if key.as_ref().is_some_and(|key| key != candidate) {
                    return Err(Error::UnknownScheme(Some(
                        "Conflicting C,system audio parameters".into(),
                    )));
                }
                key = Some(candidate.to_vec());
            }
        }
    }
    let mut key = key.ok_or_else(|| {
        Error::UnknownScheme(Some("C,system audio parameters are missing".into()))
    })?;
    key.push(0);
    let mut options = ArchiveOptions::default();
    options
        .numbers
        .insert("csystem_legacy", u64::from(legacy == Some(true)));
    options.keys.insert("csystem_audio", Secret::new(key));
    options.paths.insert("csystem_root", context.root.clone());
    Ok(options)
}
