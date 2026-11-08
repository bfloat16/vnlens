//! Locally owned AdvHD samples, never copied into the repository.
use nvlens_core::{Error, Result};
use std::{path::PathBuf, sync::atomic::AtomicBool};

fn game() -> Result<(PathBuf, nvlens_engine::Identification)> {
    nvlens_archive::init();
    nvlens_script::init();
    nvlens_image::init();
    nvlens_audio::init();
    let root = PathBuf::from(
        std::env::var_os("NVLENS_ADVHD_GAME")
            .ok_or_else(|| Error::Unsupported("Set NVLENS_ADVHD_GAME".into()))?,
    );
    let game =
        nvlens_engine::identify(&root, &AtomicBool::new(false))?.ok_or(Error::InvalidFormat)?;
    assert_eq!(game.engine, nvlens_engine::Engine::Will);
    Ok((root, game))
}
fn archives(root: &std::path::Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|s| s.eq_ignore_ascii_case("arc"))
        {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

/// NVLENS_ADVHD_GAME=<game> cargo test -p nvlens-archive --release --test advhd_game -- --ignored --nocapture
#[test]
#[ignore = "Requires NVLENS_ADVHD_GAME and original game archives"]
fn validates_advhd_scripts() -> Result<()> {
    let (root, game) = game()?;
    let catalog = nvlens_core::Catalog::load();
    let mut counts = std::collections::BTreeMap::<String, (usize, usize, usize)>::new();
    let mut hashes = Vec::new();
    let mut unknown_codes = std::collections::BTreeMap::<(String, u32), usize>::new();
    for path in archives(&root)? {
        let opened = catalog.open(&path, &game.route_path(&path).ok_or(Error::InvalidFormat)?)?;
        for entry in opened.archive.entries() {
            let Some(tag) = game.script_format_for(&entry.name) else {
                continue;
            };
            let data = opened.archive.open_entry(entry)?;
            let parsed = nvlens_script::disassemble_with_options_as(
                tag,
                &data,
                None,
                game.resource_options(),
            )
            .map_err(|e| Error::Unsupported(format!("{}:{}: {e}", path.display(), entry.name)))?;
            let Some(script) = parsed else { continue };
            assert_eq!(
                script
                    .sections
                    .iter()
                    .flat_map(|s| s.raw.iter().copied())
                    .collect::<Vec<_>>(),
                &*data
            );
            let count = counts.entry(script.format.clone()).or_default();
            count.0 += 1;
            count.1 += script.instructions.len();
            for instruction in &script.instructions {
                if instruction.opcode.operation == nvlens_script::ir::Operation::Unknown {
                    count.2 += 1;
                    *unknown_codes
                        .entry((script.format.clone(), instruction.opcode.code))
                        .or_default() += 1;
                }
            }
            if tag == "ws2/will" {
                let raw = opened.archive.open_entry_raw(entry)?;
                assert_eq!(&raw[raw.len() - 8..], &data[data.len() - 8..]);
                for (stored, plain) in raw[..raw.len() - 8].iter().zip(&data[..data.len() - 8]) {
                    assert_eq!(stored.rotate_right(2), *plain);
                }
            }
            hashes.extend(nvlens_crypto::hash::md5::digest(&data));
        }
    }
    println!(
        "AdvHD script counts {counts:?}, digest {:02x?}",
        nvlens_crypto::hash::md5::digest(&hashes)
    );
    println!("Unconfirmed native opcode counts {unknown_codes:?}");
    let vinea = root.join("Scn.arc").is_file();
    assert_eq!(
        counts.get("WS2/AdvHD"),
        Some(&if vinea {
            (207, 279637, 0)
        } else {
            (151, 104302, 0)
        })
    );
    assert_eq!(
        counts.get("Lua"),
        Some(&if vinea {
            (16, 74520, 0)
        } else {
            (21, 100289, 0)
        })
    );
    assert_eq!(
        nvlens_crypto::hash::md5::digest(&hashes),
        if vinea {
            [
                0xfc, 0x41, 0x16, 0xfe, 0x3a, 0x8f, 0x74, 0x2d, 0x3c, 0x2a, 0x94, 0x25, 0x07, 0x75,
                0x6d, 0x12,
            ]
        } else {
            [
                0x80, 0xf0, 0x10, 0x1b, 0x86, 0xd3, 0x1f, 0xc8, 0xdb, 0x8f, 0x85, 0xdc, 0xa7, 0x51,
                0x2a, 0xbf,
            ]
        }
    );
    Ok(())
}

#[test]
#[ignore = "Requires NVLENS_ADVHD_GAME and original game archives"]
fn validates_advhd_media() -> Result<()> {
    let (root, game) = game()?;
    let catalog = nvlens_core::Catalog::load();
    let mut images = 0;
    let mut frames = 0;
    let mut audio = 0;
    let mut hashes = Vec::new();
    for path in archives(&root)? {
        let opened = catalog.open(&path, &game.route_path(&path).ok_or(Error::InvalidFormat)?)?;
        for entry in opened.archive.entries() {
            let ext = entry
                .name
                .rsplit('.')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if !matches!(ext.as_str(), "png" | "pna" | "mos" | "ogg" | "wav") {
                continue;
            }
            let data = opened.archive.open_entry(entry)?;
            let check = (|| -> Result<()> {
                if matches!(ext.as_str(), "ogg" | "wav") {
                    let meta = nvlens_audio::metadata(&data)?.ok_or(Error::InvalidFormat)?;
                    if audio % 1024 == 0 {
                        let decoded = nvlens_audio::decode(&data)?.ok_or(Error::InvalidFormat)?;
                        assert_eq!(
                            (meta.channels, meta.sample_rate),
                            (decoded.meta.channels, decoded.meta.sample_rate)
                        );
                    }
                    audio += 1;
                } else {
                    let count = nvlens_image::frame_count(&data)?.ok_or(Error::InvalidFormat)?;
                    assert!(count > 0);
                    for index in 0..count {
                        let image = nvlens_image::decode_frame(&data, index)?
                            .ok_or(Error::InvalidFormat)?;
                        let nvlens_image::PixelBuffer::Rgba8(pixels) = &image.pixels else {
                            return Err(Error::InvalidFormat);
                        };
                        assert_eq!(pixels.len(), image.meta.rgba_size()?);
                        hashes.extend(nvlens_crypto::hash::md5::digest(pixels));
                        if images % 128 == 0 && index == 0 {
                            let png = image.to_png()?;
                            assert_eq!(
                                nvlens_image::metadata(&png)?.ok_or(Error::InvalidFormat)?,
                                image.meta
                            );
                        }
                    }
                    images += 1;
                    frames += count;
                }
                Ok(())
            })();
            check.map_err(|e| {
                Error::Unsupported(format!("{}:{}: {e}", path.display(), entry.name))
            })?;
        }
        println!(
            "{}: {images} images / {frames} frames, {audio} audio",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
    }
    println!(
        "AdvHD media digest {:02x?}",
        nvlens_crypto::hash::md5::digest(&hashes)
    );
    let vinea = root.join("Scn.arc").is_file();
    assert_eq!(
        (images, frames, audio),
        if vinea {
            (1489, 5350, 16716)
        } else {
            (867, 6144, 4758)
        }
    );
    assert_eq!(
        nvlens_crypto::hash::md5::digest(&hashes),
        if vinea {
            [
                0x36, 0xf6, 0xd9, 0x65, 0xac, 0xa0, 0x57, 0x47, 0x4e, 0xa7, 0x1e, 0x83, 0xfe, 0x9f,
                0xac, 0xb1,
            ]
        } else {
            [
                0x01, 0xb1, 0x02, 0x27, 0x81, 0xb9, 0xf4, 0x9e, 0x96, 0xea, 0xa5, 0x50, 0xf6, 0xb5,
                0x43, 0x01,
            ]
        }
    );
    Ok(())
}
