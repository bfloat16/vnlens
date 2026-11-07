//! smash::fw PackFile fingerprints and verified GetPackSolt() parameters.
use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::{ArchiveOptions, Result, Secret};
use nvlens_io::pe::PeImage;
fn pe(pe: &PeImage<'_>) -> Result<bool> {
    Ok(has(pe, b"smash")? && has(pe, b"PackFile")?)
}
fn layout(_: &std::path::Path) -> bool {
    false
}
fn resolve(
    _: &std::path::Path,
    executables: &[std::path::PathBuf],
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<ArchiveOptions> {
    let mut options = ArchiveOptions::default();
    for path in executables {
        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(nvlens_core::Error::Cancelled);
        }
        let view = nvlens_io::ArcView::open(path)?;
        let Some(pe) = PeImage::parse(view.slice(0, view.len())?)? else {
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
        return Err(nvlens_core::Error::UnknownScheme(Some(
            "AGES-MK2 scramble parameters were not identified in PE".into(),
        )));
    }
    // Verify required external assets before granting an archive route.
    for key in [
        nvlens_bin::keys::ages_mk2::SCRAMBLE_BASE,
        nvlens_bin::keys::ages_mk2::EPK_BLOWFISH_DATAS,
        nvlens_bin::keys::ages_mk2::SOUND_BLOWFISH_DATAS,
        nvlens_bin::keys::ages_mk2::SOUND_MD5_SALT,
    ] {
        nvlens_bin::load(key)?;
    }
    Ok(options)
}
nvlens_core::inventory::submit! { Detector { pe, layout, engine: Engine::AgesMk2, resolve } }
