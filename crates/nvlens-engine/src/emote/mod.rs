//! PSBFile plugin identity, distinct from games merely embedding EmotePlayer.
use crate::{
    Engine,
    detect::{Detector, has},
};
use nvlens_core::{ArchiveOptions, Error, Result, Secret};
use nvlens_io::{BinaryWriter, pe::PeImage};
fn pe(pe: &PeImage<'_>) -> Result<bool> {
    Ok(has(pe, b"PSBFile")? && has(pe, b"psbfile.dll")?)
}
fn layout(root: &std::path::Path) -> bool {
    root.join("plugin/psbfile.dll").is_file() && root.join("data").is_dir()
}
fn resolve(
    _: &std::path::Path,
    _: &[std::path::PathBuf],
    _: &std::sync::atomic::AtomicBool,
) -> Result<ArchiveOptions> {
    let mut options = ArchiveOptions::default();
    if let Ok(key) = std::env::var("NVLENS_MDF_KEY")
        && !key.is_empty()
    {
        options
            .keys
            .insert("mdf_base", Secret::new(key.into_bytes()));
    }
    let length = match std::env::var("NVLENS_MDF_KEY_LEN") {
        Ok(value) => value
            .parse::<u64>()
            .ok()
            .filter(|&value| value > 0)
            .ok_or_else(|| Error::UnknownScheme(Some("Invalid MDF key length".into())))?,
        Err(_) => 0x83,
    };
    options.numbers.insert("mdf_length", length);
    if let Ok(key) = std::env::var("NVLENS_PSB_KEY") {
        let key = key
            .parse::<u32>()
            .map_err(|_| Error::UnknownScheme(Some("Invalid PSB key".into())))?;
        let mut bytes = vec![0; 4];
        BinaryWriter::u32_le(key, &mut bytes);
        options.keys.insert("psb", Secret::new(bytes));
    }
    Ok(options)
}
nvlens_core::inventory::submit! { Detector { pe, layout, engine: Engine::Emote, resolve } }
