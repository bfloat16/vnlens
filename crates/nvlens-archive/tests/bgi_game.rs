//! Requires the locally owned BGI game; no game assets are committed.
use nvlens_core::{Catalog, Result};
use std::{path::PathBuf, sync::atomic::AtomicBool};

/// NVLENS_BGI_GAME=<game> cargo test -p nvlens-archive --release --test bgi_game -- --ignored --nocapture
#[test]
#[ignore = "Requires NVLENS_BGI_GAME and original archives"]
fn validates_bgi_game_resources() -> Result<()> {
    nvlens_archive::init();
    nvlens_image::init();
    nvlens_audio::init();
    let root = PathBuf::from(
        std::env::var_os("NVLENS_BGI_GAME")
            .ok_or_else(|| nvlens_core::Error::Unsupported("Set NVLENS_BGI_GAME".into()))?,
    );
    let game = nvlens_engine::identify(&root, &AtomicBool::new(false))?
        .ok_or(nvlens_core::Error::InvalidFormat)?;
    let catalog = Catalog::load();
    let mut files = Vec::new();
    for directory in [&root, &root.join("Archive")] {
        for entry in std::fs::read_dir(directory)? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "arc") {
                files.push(path);
            }
        }
    }
    files.sort();
    let mut counts = [0usize; 4];
    let mut decoded = std::collections::BTreeSet::new();
    let mut scripts = std::collections::BTreeMap::<String, (usize, usize)>::new();
    for path in files {
        let archive = catalog.open(
            &path,
            &game
                .route_path(&path)
                .ok_or(nvlens_core::Error::InvalidFormat)?,
        )?;
        for entry in archive.archive.entries() {
            let data = archive.archive.open_entry(entry)?;
            let result = (|| -> Result<()> {
                if let Some(meta) = nvlens_image::metadata(&data)? {
                    let version = if data.starts_with(b"CompressedBG___") {
                        nvlens_io::BinaryReader::u16_le(&data[46..])
                    } else {
                        u16::MAX
                    };
                    if decoded.insert((version, meta.bpp)) {
                        let start = std::time::Instant::now();
                        println!(
                            "Decoding representative {}:{} v{version} {}x{} {}bpp",
                            path.display(),
                            entry.name,
                            meta.width,
                            meta.height,
                            meta.bpp
                        );
                        let image = nvlens_image::decode(&data)?
                            .ok_or(nvlens_core::Error::InvalidFormat)?;
                        assert_eq!(meta, image.meta);
                        println!("Decoded in {:?}", start.elapsed());
                    }
                    counts[0] += 1;
                } else if let Some(meta) = nvlens_audio::metadata(&data)? {
                    if counts[1] % 1024 == 0 {
                        let pcm = nvlens_audio::decode(&data)?
                            .ok_or(nvlens_core::Error::InvalidFormat)?;
                        assert_eq!(meta.channels, pcm.meta.channels);
                        assert_eq!(meta.sample_rate, pcm.meta.sample_rate);
                    }
                    counts[1] += 1;
                } else {
                    if let Some(script) = nvlens_script::disassemble_as("script/bgi", &data, None)?
                    {
                        assert!(!script.instructions.is_empty());
                        assert_eq!(
                            script
                                .sections
                                .iter()
                                .flat_map(|s| s.raw.iter().copied())
                                .collect::<Vec<_>>(),
                            &*data
                        );
                        let count = scripts.entry(script.format).or_default();
                        count.0 += 1;
                        count.1 += script.instructions.len();
                    }
                    counts[2] += 1;
                }
                Ok(())
            })();
            if let Err(error) = result {
                eprintln!("{}:{}: {error}", path.display(), entry.name);
                counts[3] += 1;
            }
        }
        println!(
            "{} {:?}",
            path.file_name().unwrap_or_default().to_string_lossy(),
            counts
        );
    }
    assert_eq!(counts[3], 0);
    println!("Validated BGI image/audio/other/error counts: {counts:?}");
    println!("Script files and instructions: {scripts:?}");
    Ok(())
}
