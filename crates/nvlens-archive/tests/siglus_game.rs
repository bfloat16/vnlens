//! Local licensed sample validation; never copies game resources into the repo.
//! NVLENS_SIGLUS_GAME=<root> cargo test -p nvlens-archive --release --test siglus_game -- --ignored --nocapture
use nvlens_core::{Error, Result};
use nvlens_io::BinaryWriter;
use std::{path::PathBuf, sync::atomic::AtomicBool};

#[test]
#[ignore = "Requires NVLENS_SIGLUS_GAME and original SiglusEngine game files"]
fn validates_siglus_game() -> Result<()> {
    nvlens_archive::init();
    nvlens_image::init();
    nvlens_audio::init();
    nvlens_script::init();
    let root = PathBuf::from(
        std::env::var_os("NVLENS_SIGLUS_GAME")
            .ok_or_else(|| Error::Unsupported("Set NVLENS_SIGLUS_GAME".into()))?,
    );
    let game =
        nvlens_engine::identify(&root, &AtomicBool::new(false))?.ok_or(Error::InvalidFormat)?;
    assert_eq!(game.engine, nvlens_engine::Engine::Siglus);
    let catalog = nvlens_core::Catalog::load();
    let scene = catalog.open(
        root.join("Scene.pck"),
        &game.route("Scene.pck").ok_or(Error::InvalidFormat)?,
    )?;
    let mut instructions = 0;
    let mut unknown = 0;
    let mut scene_hashes = Vec::new();
    for entry in scene.archive.entries() {
        let bytes = scene.archive.open_entry(entry)?;
        scene_hashes.push((entry.name.clone(), nvlens_crypto::hash::md5::digest(&bytes)));
        let script = nvlens_script::disassemble_as("script/siglus", &bytes, None)
            .map_err(|e| Error::Unsupported(format!("{}: {e}", entry.name)))?
            .ok_or(Error::InvalidFormat)?;
        instructions += script.instructions.len();
        unknown += script
            .instructions
            .iter()
            .filter(|i| i.opcode.operation == nvlens_script::ir::Operation::Unknown)
            .count();
        assert_eq!(script.sections[0].raw, &*bytes);
    }
    println!(
        "Scenes: {}; instructions: {instructions}; unknown: {unknown}",
        scene.archive.entries().len()
    );
    assert_eq!(scene.archive.entries().len(), 49);
    assert_eq!(instructions, 1_012_740);
    assert_eq!(unknown, 0);
    scene_hashes.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        hash(
            &scene_hashes
                .iter()
                .flat_map(|(_, h)| h.iter().copied())
                .collect::<Vec<_>>()
        ),
        "2de81c5725980fe44a6273921a22d883"
    );
    let config = catalog.open(
        root.join("Gameexe.dat"),
        &game.route("Gameexe.dat").ok_or(Error::InvalidFormat)?,
    )?;
    assert!(std::str::from_utf8(&config.archive.open_entry(&config.archive.entries()[0])?).is_ok());
    let mut images = 0;
    let mut frames = 0;
    let mut files = std::fs::read_dir(root.join("g00"))?.collect::<std::io::Result<Vec<_>>>()?;
    files.sort_by_key(|f| f.path());
    for file in files {
        let bytes = std::fs::read(file.path())?;
        let count = nvlens_image::frame_count(&bytes)?.ok_or(Error::InvalidFormat)?;
        images += 1;
        frames += count;
        if images % 97 == 0 || count > 1 && images % 13 == 0 {
            for frame in [0, count - 1] {
                let image = nvlens_image::decode_frame(&bytes, frame)
                    .map_err(|e| {
                        Error::Unsupported(format!("{} frame {frame}: {e}", file.path().display()))
                    })?
                    .ok_or(Error::InvalidFormat)?;
                if let nvlens_image::PixelBuffer::Bgra8(pixels) = &image.pixels {
                    assert_eq!(pixels.len(), image.meta.rgba_size()?);
                }
            }
        }
    }
    println!("Images: {images}; frames: {frames}");
    assert_eq!((images, frames), (1064, 2244));
    for (name, expected) in [
        ("bg01a.g00", "9bcbb24bedb34fc858976526724e8e74"),
        ("bs2_hh010101.g00", "4b0e26fd4e43e0a81a2e8a7b68957657"),
        ("ef_em21.g00", "e4e218063930dfee16bf587954bda590"),
        ("__sys_bk_btn01.g00", "1c3c1dbac99a24a06b3d2b78717617ad"),
    ] {
        let image = nvlens_image::decode(&std::fs::read(root.join("g00").join(name))?)?
            .ok_or(Error::InvalidFormat)?;
        if let nvlens_image::PixelBuffer::Bgra8(bytes) = image.pixels {
            assert_eq!(hash(&bytes), expected, "{name}");
        } else {
            return Err(Error::InvalidFormat);
        }
    }
    let mut audio = 0;
    let mut audio_hashes = Vec::new();
    for file in std::fs::read_dir(root.join("wav"))? {
        let path = file?.path();
        if path
            .extension()
            .is_none_or(|e| !e.eq_ignore_ascii_case("nwa"))
        {
            continue;
        }
        let bytes = std::fs::read(&path)?;
        let pcm = nvlens_audio::decode(&bytes)
            .map_err(|e| Error::Unsupported(format!("{}: {e}", path.display())))?
            .ok_or(Error::InvalidFormat)?;
        assert_eq!(
            pcm.meta.frames.map(|n| n * u64::from(pcm.meta.channels)),
            Some(pcm.samples.len() as u64)
        );
        let mut raw = Vec::with_capacity(pcm.samples.len() * 2);
        for &sample in &*pcm.samples {
            let mut word = [0; 2];
            BinaryWriter::u16_le((sample * 32768.) as i16 as u16, &mut word);
            raw.extend(word);
        }
        audio_hashes.push((
            path.file_name().unwrap_or_default().to_owned(),
            nvlens_crypto::hash::md5::digest(&raw),
        ));
        audio += 1;
    }
    audio_hashes.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        hash(
            &audio_hashes
                .iter()
                .flat_map(|(_, h)| h.iter().copied())
                .collect::<Vec<_>>()
        ),
        "b94971150571145cdcdc8e874c24686c"
    );
    let mut voices = 0;
    for file in std::fs::read_dir(root.join("koe"))? {
        let path = file?.path();
        let Some(route) = game.route_path(&path) else {
            continue;
        };
        let archive = catalog.open(&path, &route)?;
        voices += archive.archive.entries().len();
        for entry in archive.archive.entries().iter().step_by(1024) {
            let bytes = archive.archive.open_entry(entry)?;
            assert!(nvlens_audio::decode(&bytes)?.is_some());
        }
    }
    println!("NWA: {audio}; voices: {voices}");
    assert_eq!((audio, voices), (75, 7800));
    let mut movies = 0;
    for file in std::fs::read_dir(root.join("mov"))? {
        let path = file?.path();
        let Some(route) = game.route_path(&path) else {
            continue;
        };
        let archive = catalog.open(&path, &route)?;
        let bytes = archive.archive.open_entry(&archive.archive.entries()[0])?;
        assert!(bytes.starts_with(b"OggS"));
        movies += 1;
    }
    let mut animations = 0;
    for file in std::fs::read_dir(root.join("gan"))? {
        let bytes = std::fs::read(file?.path())?;
        let script = nvlens_script::disassemble_as("script/siglus", &bytes, None)?
            .ok_or(Error::InvalidFormat)?;
        assert!(script.instructions.iter().all(|i| i.opcode.operation
            == nvlens_script::ir::Operation::Data(nvlens_script::ir::DataOperation::Record)));
        animations += 1;
    }
    assert_eq!((movies, animations), (28, 6));
    println!("OMV streams: {movies}; GAN animation definitions: {animations}");
    Ok(())
}

fn hash(bytes: &[u8]) -> String {
    nvlens_crypto::hash::md5::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
#[ignore = "Requires NVLENS_SAYAGATARI_GAME; checks locally owned Siglus archives and scripts without writing resources"]
fn validates_sayagatari() -> Result<()> {
    let root =
        PathBuf::from(std::env::var_os("NVLENS_SAYAGATARI_GAME").ok_or(Error::InvalidFormat)?);
    nvlens_archive::init();
    nvlens_script::init();
    let game =
        nvlens_engine::identify(&root, &AtomicBool::new(false))?.ok_or(Error::InvalidFormat)?;
    assert_eq!(game.engine, nvlens_engine::Engine::Siglus);
    let catalog = nvlens_core::Catalog::load();
    let scenes = catalog
        .open(
            root.join("Scene.pck"),
            &game.route("Scene.pck").ok_or(Error::InvalidFormat)?,
        )?
        .archive;
    let mut digests = Vec::new();
    let mut instructions = 0;
    let mut unknown = 0;
    for entry in scenes.entries() {
        let bytes = scenes.open_entry(entry)?;
        let script = nvlens_script::disassemble_as("script/siglus", &bytes, None)
            .map_err(|e| Error::Unsupported(format!("{}: {e}", entry.name)))?
            .ok_or(Error::InvalidFormat)?;
        assert_eq!(script.sections[0].raw, &*bytes);
        instructions += script.instructions.len();
        unknown += script
            .instructions
            .iter()
            .filter(|i| i.opcode.operation == nvlens_script::ir::Operation::Unknown)
            .count();
        digests.push((entry.name.clone(), nvlens_crypto::hash::md5::digest(&bytes)));
    }
    digests.sort_by(|a, b| a.0.cmp(&b.0));
    let digest = hash(
        &digests
            .iter()
            .flat_map(|(_, h)| h.iter().copied())
            .collect::<Vec<_>>(),
    );
    let config = catalog
        .open(
            root.join("Gameexe.dat"),
            &game.route("Gameexe.dat").ok_or(Error::InvalidFormat)?,
        )?
        .archive;
    let bytes = config.open_entry(&config.entries()[0])?;
    assert!(std::str::from_utf8(&bytes).is_ok());
    assert_eq!(unknown, 0);
    assert_eq!(scenes.entries().len(), 92);
    assert_eq!(instructions, 675_157);
    assert_eq!(digest, "8a3521c7cdf41ac5923affa5e9446f1d");
    assert_eq!(hash(&bytes), "5e36968f4e70370a3ee0f26b9d0cbd6d");
    println!(
        "Sayagatari: {} scenes; {instructions} instructions; {unknown} unknown; scenes MD5 {digest}; config MD5 {}",
        scenes.entries().len(),
        hash(&bytes)
    );
    Ok(())
}
