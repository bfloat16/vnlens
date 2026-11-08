//! Local ExHIBIT samples stay outside the repository. No target code is run.
use nvlens_core::{Error, Result};
use std::{path::PathBuf, sync::atomic::AtomicBool};

/// NVLENS_EXHIBIT_GAME=<game> cargo test -p nvlens-archive --release --test exhibit_game -- --ignored --nocapture
#[test]
#[ignore = "Requires NVLENS_EXHIBIT_GAME and original game files"]
fn validates_exhibit_resources() -> Result<()> {
    nvlens_archive::init();
    nvlens_image::init();
    nvlens_audio::init();
    nvlens_script::init();
    let root = PathBuf::from(std::env::var_os("NVLENS_EXHIBIT_GAME").ok_or(Error::InvalidFormat)?);
    let volume1 = root.join("StraySheepVol1.exe").is_file();
    let game =
        nvlens_engine::identify(&root, &AtomicBool::new(false))?.ok_or(Error::InvalidFormat)?;
    assert_eq!(game.engine, nvlens_engine::Engine::Exhibit);
    let catalog = nvlens_core::Catalog::load();
    let mut pending = vec![root];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    let mut images = 0;
    let mut scripts = 0;
    let mut commands = 0;
    let mut audio = 0;
    let mut loose_audio = 0;
    let mut configs = 0;
    let mut animations = 0;
    let mut frames = 0;
    let mut animation_hashes = Vec::new();
    let mut unknown = std::collections::BTreeMap::<u32, usize>::new();
    let mut image_hashes = Vec::new();
    let mut script_hashes = Vec::new();
    for path in files {
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        let result = (|| -> Result<()> {
            match ext {
                "rnf" | "ini" => {
                    let bytes = std::fs::read(&path)?;
                    assert!(nvlens_script::decode_text_as("rld/exhibit", &bytes)?.is_some());
                    configs += 1;
                }
                "ogg" | "wav" => {
                    let bytes = std::fs::read(&path)?;
                    let meta = nvlens_audio::metadata(&bytes)?.ok_or(Error::InvalidFormat)?;
                    if loose_audio % 32 == 0 {
                        let decoded = nvlens_audio::decode(&bytes)?.ok_or(Error::InvalidFormat)?;
                        assert_eq!(decoded.meta.channels, meta.channels);
                        assert_eq!(decoded.meta.sample_rate, meta.sample_rate);
                    }
                    loose_audio += 1;
                }
                "dlt" => {
                    let bytes = std::fs::read(&path)?;
                    let count = nvlens_image::frame_count(&bytes)?.ok_or(Error::InvalidFormat)?;
                    assert!(count > 0);
                    for index in [0, count - 1] {
                        let image = nvlens_image::decode_frame(&bytes, index)?
                            .ok_or(Error::InvalidFormat)?;
                        let nvlens_image::PixelBuffer::Rgba8(pixels) = image.pixels else {
                            return Err(Error::InvalidFormat);
                        };
                        assert_eq!(pixels.len(), image.meta.rgba_size()?);
                        animation_hashes.extend(nvlens_crypto::hash::md5::digest(&pixels));
                    }
                    animations += 1;
                    frames += count;
                }
                "gyu" => {
                    let bytes = std::fs::read(&path)?;
                    let meta = nvlens_image::metadata(&bytes)?.ok_or(Error::InvalidFormat)?;
                    let image = nvlens_image::decode(&bytes)?.ok_or(Error::InvalidFormat)?;
                    assert_eq!(meta, image.meta);
                    let nvlens_image::PixelBuffer::Rgba8(pixels) = image.pixels else {
                        return Err(Error::InvalidFormat);
                    };
                    assert_eq!(pixels.len(), meta.rgba_size()?);
                    image_hashes.extend(nvlens_crypto::hash::md5::digest(&pixels));
                    images += 1;
                }
                "rld" => {
                    let bytes = std::fs::read(&path)?;
                    let bytes =
                        nvlens_script::decode_as("rld/exhibit", &bytes, game.resource_options())?;
                    let script = nvlens_script::disassemble_as("rld/exhibit", &bytes, None)?
                        .ok_or(Error::InvalidFormat)?;
                    assert_eq!(
                        script
                            .sections
                            .iter()
                            .flat_map(|s| s.raw.iter().copied())
                            .collect::<Vec<_>>(),
                        &*bytes
                    );
                    for instruction in &script.instructions {
                        if instruction.opcode.operation == nvlens_script::ir::Operation::Unknown {
                            *unknown.entry(instruction.opcode.code).or_default() += 1;
                        }
                    }
                    commands += script.instructions.len();
                    assert!(!script.sections.iter().any(|s| s.name == "trailing"));
                    script_hashes.extend(nvlens_crypto::hash::md5::digest(&bytes));
                    scripts += 1;
                }
                "grp" if path.file_stem().is_some_and(|s| s == "res2000") => {
                    let opened = catalog
                        .open(&path, &game.route_path(&path).ok_or(Error::InvalidFormat)?)?;
                    for (i, entry) in opened.archive.entries().iter().enumerate() {
                        let bytes = opened.archive.open_entry(entry)?;
                        let meta = nvlens_audio::metadata(&bytes)?.ok_or(Error::InvalidFormat)?;
                        if i % 1024 == 0 {
                            let decoded =
                                nvlens_audio::decode(&bytes)?.ok_or(Error::InvalidFormat)?;
                            assert_eq!(meta.channels, decoded.meta.channels);
                            assert_eq!(meta.sample_rate, decoded.meta.sample_rate);
                        }
                        audio += 1;
                    }
                    let volume = path.with_file_name("res2001.grp");
                    let direct = catalog.open(
                        &volume,
                        &game.route_path(&volume).ok_or(Error::InvalidFormat)?,
                    )?;
                    assert_eq!(
                        direct.archive.entries().len(),
                        opened.archive.entries().len()
                    );
                    for (a, b) in direct
                        .archive
                        .entries()
                        .iter()
                        .zip(opened.archive.entries())
                    {
                        assert_eq!((&a.name, a.offset, a.size), (&b.name, b.offset, b.size));
                    }
                }
                _ => {}
            }
            Ok(())
        })();
        result.map_err(|e| Error::Unsupported(format!("{}: {e}", path.display())))?;
    }
    assert!(unknown.is_empty());
    assert_eq!(
        (images, scripts, commands, audio, animations, frames),
        if volume1 {
            (1688, 65, 16847, 3179, 7, 491)
        } else {
            (1891, 76, 15600, 2594, 5, 271)
        }
    );
    assert_eq!(
        nvlens_crypto::hash::md5::digest(&image_hashes),
        if volume1 {
            [
                0x9f, 0xab, 0xb5, 0xdc, 0x4b, 0x81, 0x16, 0xc8, 0x80, 0x18, 0x80, 0x27, 0x20, 0x25,
                0x1c, 0xff,
            ]
        } else {
            [
                0x65, 0xae, 0xac, 0x21, 0xdd, 0x79, 0xbe, 0x44, 0xc3, 0x8b, 0xd4, 0x6b, 0xd2, 0x89,
                0x39, 0x23,
            ]
        }
    );
    assert_eq!(
        nvlens_crypto::hash::md5::digest(&animation_hashes),
        if volume1 {
            [
                0xf1, 0x95, 0x90, 0x82, 0x1d, 0xcd, 0x06, 0xb6, 0x63, 0x23, 0x44, 0x1b, 0xf0, 0xab,
                0x43, 0x86,
            ]
        } else {
            [
                0x4d, 0xcc, 0x5e, 0xaf, 0xef, 0x87, 0x08, 0xed, 0xed, 0x88, 0x83, 0x7c, 0x73, 0xe0,
                0xac, 0xac,
            ]
        }
    );
    println!("Loose resources: {loose_audio} audio, {configs} configuration files");
    println!(
        "DLT: {animations} animations, {frames} frames; digest {:02x?}",
        nvlens_crypto::hash::md5::digest(&animation_hashes)
    );
    println!(
        "ExHIBIT: {images} images, {scripts} scripts, {commands} commands, {audio} archived audio; unknown {unknown:?}"
    );
    println!(
        "Image digest {:02x?}; script digest {:02x?}",
        nvlens_crypto::hash::md5::digest(&image_hashes),
        nvlens_crypto::hash::md5::digest(&script_hashes)
    );
    Ok(())
}
