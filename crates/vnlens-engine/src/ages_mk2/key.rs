//! AGES-MK2 scramble parameter recovery and external table verification.
use crate::context::Context;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_core::{ArchiveOptions, Error, Result, Secret};

pub(super) fn resolve(
    context: &Context,
    executables: &[PathBuf],
    cancelled: &AtomicBool,
) -> Result<ArchiveOptions> {
    let mut options = ArchiveOptions::default();
    for path in executables {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let view = context.files.open(path)?;
        let Some(pe) = context.image(&view, cancelled)? else {
            continue;
        };
        for (label, key) in [
            ("resident", &b"11f32b0d98cfe8395fe4deeb75fff578"[..]),
            ("obb", &b"mt23227A4662AB769ADF39B7A905348613"[..]),
        ] {
            // Key bytes are case-sensitive even though identity markers are not.
            for section in &pe.sections {
                if pe
                    .section_data(section)?
                    .windows(key.len())
                    .any(|bytes| bytes == key)
                {
                    options.keys.insert(label, Secret::new(key.to_vec()));
                    break;
                }
            }
        }
    }
    if options.keys.is_empty() {
        return Err(Error::UnknownScheme(Some(
            "AGES-MK2 scramble parameters were not identified in PE".into(),
        )));
    }
    // Verify required external assets before granting an archive route.
    for key in [
        vnlens_bin::keys::ages_mk2::SCRAMBLE_BASE,
        vnlens_bin::keys::ages_mk2::EPK_BLOWFISH_DATAS,
        vnlens_bin::keys::ages_mk2::SOUND_BLOWFISH_DATAS,
        vnlens_bin::keys::ages_mk2::SOUND_MD5_SALT,
    ] {
        vnlens_bin::load(key)?;
    }
    Ok(options)
}
