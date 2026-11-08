//! Licensed D.C.5 to 4 Luminous Memories sample check. Set NVLENS_HXV4_GAME to the game root and run:
//! cargo test -p nvlens-archive --test krkrz_hxv4_game -- --ignored --nocapture
//! No sample contents or recovered keys are written to disk.
use nvlens_core::{Catalog, Result};

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::atomic::AtomicBool,
};
#[test]
#[ignore = "Requires NVLENS_HXV4_GAME pointing to a licensed krkrz_hxv4 installation"]
fn validates_dc5t4lm() -> Result<()> {
    let root = PathBuf::from(
        std::env::var_os("NVLENS_HXV4_GAME")
            .ok_or_else(|| nvlens_core::Error::Unsupported("Set NVLENS_HXV4_GAME".into()))?,
    );
    nvlens_archive::init();
    nvlens_image::init();
    nvlens_audio::init();
    nvlens_script::init();
    let game = nvlens_engine::identify(&root, &AtomicBool::new(false))?
        .ok_or(nvlens_core::Error::InvalidFormat)?;
    assert_eq!(game.engine, nvlens_engine::Engine::KrkrzHxv4);
    let catalog = Catalog::load();
    let mut files = std::fs::read_dir(&root)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    files.sort();
    for file in files {
        if !file
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("xp3"))
        {
            continue;
        }
        let route = game
            .route_path(&file)
            .ok_or(nvlens_core::Error::InvalidFormat)?;
        let archive = catalog.open(&file, &route)?.archive;
        let mut types = BTreeMap::<String, usize>::new();
        let mut instructions = 0usize;
        let mut unknown_opcodes = BTreeMap::<u32, usize>::new();
        let mut pixel_hashes = Vec::new();
        let mut hash_directories = BTreeSet::new();
        for (index, entry) in archive.entries().iter().enumerate() {
            if entry.name != "startup.tjs" {
                let (directory, filename) = entry
                    .name
                    .split_once('/')
                    .ok_or(nvlens_core::Error::InvalidFormat)?;
                assert_eq!((directory.len(), filename.len()), (16, 64));
                assert!(
                    directory
                        .bytes()
                        .chain(filename.bytes())
                        .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
                );
                hash_directories.insert(directory.to_owned());
            }
            let bytes = archive.open_entry(entry)?;
            let kind = if bytes.starts_with(b"TLG") {
                let image =
                    nvlens_image::decode(&bytes)?.ok_or(nvlens_core::Error::InvalidFormat)?;
                if let nvlens_image::PixelBuffer::Bgra8(pixels) = image.pixels {
                    pixel_hashes.extend(nvlens_crypto::hash::md5::digest(&pixels));
                }
                String::from_utf8_lossy(&bytes[..4]).into_owned()
            } else if bytes.starts_with(b"OggS") {
                let meta =
                    nvlens_audio::metadata(&bytes)?.ok_or(nvlens_core::Error::InvalidFormat)?;
                if index % 251 == 0 {
                    let pcm =
                        nvlens_audio::decode(&bytes)?.ok_or(nvlens_core::Error::InvalidFormat)?;
                    assert_eq!(pcm.meta.frames, meta.frames);
                    assert!(pcm.samples.iter().all(|v| v.is_finite()));
                }
                meta.codec.into()
            } else if bytes.starts_with(b"TJS2") {
                let script = nvlens_script::disassemble_as("script/krkr", &bytes, None)?
                    .ok_or(nvlens_core::Error::InvalidFormat)?;
                instructions += script.instructions.len();
                for instruction in &script.instructions {
                    if instruction.opcode.operation == nvlens_script::ir::Operation::Unknown {
                        *unknown_opcodes.entry(instruction.opcode.code).or_default() += 1;
                        assert!(instruction.opcode.native_mnemonic.is_some());
                        assert!(instruction.span.size > 0);
                    }
                }
                "TJS2".into()
            } else if bytes.starts_with(b"PSB") {
                "PSB".into()
            } else if bytes.starts_with(b"\x89PNG") {
                assert!(nvlens_image::metadata(&bytes)?.is_some());
                if index % 251 == 0 {
                    assert!(nvlens_image::decode(&bytes)?.is_some());
                }
                "PNG".into()
            } else if bytes.starts_with(b"\xfe\xfe") {
                assert!(nvlens_script::decode_text_as("script/krkr", &bytes)?.is_some());
                "TJS text".into()
            } else if bytes.starts_with(b"\xff\xfe") {
                "UTF-16".into()
            } else {
                "Other".into()
            };
            *types.entry(kind).or_default() += 1;
        }
        let name = file.file_name().unwrap_or_default().to_string_lossy();
        let expected = match name.as_ref() {
            "bgimage.xp3" => 892,
            "data.xp3" => 2097,
            "evimage.xp3" => 160,
            "fgimage.xp3" => 2794,
            "voice.xp3" => 7475,
            _ => return Err(nvlens_core::Error::InvalidFormat),
        };
        assert_eq!(archive.entries().len(), expected);
        // Layout is known, but these native operations are not yet mapped to
        // shared semantics. Keep their placeholders and original identities.
        assert_eq!(
            unknown_opcodes,
            if name == "data.xp3" {
                BTreeMap::from([
                    (0, 442),
                    (5, 7998),
                    (6, 2341),
                    (11, 773),
                    (12, 280),
                    (14, 1231),
                    (83, 580),
                    (84, 1159),
                    (85, 249),
                    (86, 29),
                    (87, 14),
                    (88, 454),
                    (93, 554),
                    (94, 372),
                    (118, 22401),
                    (123, 2449),
                    (125, 537),
                    (126, 537),
                ])
            } else {
                BTreeMap::new()
            }
        );
        if name == "data.xp3" {
            assert_eq!(instructions, 383447);
        }
        if name == "fgimage.xp3" {
            let digest = nvlens_crypto::hash::md5::digest(&pixel_hashes);
            assert_eq!(
                digest,
                [
                    0x9e, 0x87, 0x33, 0x0a, 0xdc, 0x3a, 0xd3, 0x74, 0x6e, 0x1a, 0x31, 0x27, 0x14,
                    0x9d, 0x73, 0x1e
                ]
            );
        }
        eprintln!(
            "{}: {} checked entries, {} hash directories, {:?}",
            file.file_name().unwrap_or_default().to_string_lossy(),
            archive.entries().len(),
            hash_directories.len(),
            types
        );
    }
    Ok(())
}

#[test]
#[ignore = "Requires NVLENS_HXV4_GAME; validates recovered names against original hashes"]
fn validates_explicit_name_recovery() -> Result<()> {
    use nvlens_archive::krkr::NameRecovery;
    use nvlens_crypto::hash::hxv4;
    let root = PathBuf::from(
        std::env::var_os("NVLENS_HXV4_GAME")
            .ok_or_else(|| nvlens_core::Error::Unsupported("Set NVLENS_HXV4_GAME".into()))?,
    );
    let cancel = AtomicBool::new(false);
    let game = nvlens_engine::identify(&root, &cancel)?.ok_or(nvlens_core::Error::InvalidFormat)?;
    let mut inputs = Vec::new();
    for entry in std::fs::read_dir(&root)? {
        let path = entry?.path();
        if let Some(route) = game.route_path(&path)
            && route.tag == "xp3/krkr"
        {
            inputs.push((path, route.options));
        }
    }
    inputs.sort_by(|a, b| a.0.cmp(&b.0));
    let mut recovery = NameRecovery::open(&inputs, &cancel)?;
    assert_eq!(recovery.progress().completed, 0);
    while recovery.step(&cancel)? {}
    assert_eq!(recovery.progress().failed, 0);
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02X}")).collect::<String>();
    let mut files = 0;
    let mut dirs = 0;
    let mut scenes = 0;
    for (path, names) in recovery.paths() {
        let mut restored = 0;
        let mut voice_types = BTreeMap::<String, usize>::new();
        let archive = Catalog::load()
            .open(
                &path,
                &game
                    .route_path(&path)
                    .ok_or(nvlens_core::Error::InvalidFormat)?,
            )?
            .archive;
        assert_eq!(names.len(), archive.entries().len());
        for (entry, name) in archive.entries().iter().zip(names) {
            if name.ends_with(".ks.scn") {
                let data = archive.open_entry(entry)?;
                let text = nvlens_script::decode_text_as("script/krkr", &data)?
                    .ok_or(nvlens_core::Error::InvalidFormat)?;
                assert!(text.contains("\"scenes\""));
                scenes += 1;
            }
            let Some((dir_hash, file_hash)) = entry.name.split_once('/') else {
                assert_eq!(entry.name, name);
                continue;
            };
            let (directory, file) = name.rsplit_once('/').unwrap_or(("", &name));
            if file != file_hash {
                assert_eq!(hex(&hxv4::filename(file, "xp3hnp")), file_hash);
                files += 1;
                restored += 1;
                *voice_types
                    .entry(file.rsplit('.').next().unwrap_or("").to_owned())
                    .or_default() += 1;
            }
            if directory != dir_hash {
                let direct = hex(&hxv4::directory(directory, "xp3hnp"));
                let slash = hex(&hxv4::directory(&format!("{directory}/"), "xp3hnp"));
                assert!(direct == dir_hash || slash == dir_hash);
                dirs += 1;
            }
        }
        if path.file_name().is_some_and(|name| name == "voice.xp3") {
            assert_eq!(restored, 6445);
            assert_eq!(voice_types.get("opus"), Some(&4580));
            assert_eq!(voice_types.get("sli"), Some(&1865));
            println!(
                "voice.xp3: {restored}/{} names restored; {voice_types:?}",
                archive.entries().len()
            );
        }
    }
    assert!(files > 0 && dirs > 0);
    assert_eq!(scenes, 59);
    println!(
        "Verified {files} recovered filenames, {dirs} directory mappings and {scenes} PSB scenario previews; {:?}",
        recovery.progress()
    );
    Ok(())
}

#[test]
#[ignore = "Requires NVLENS_COCORO_GAME; reads locally owned archives and PSB scenarios, without a window or output files"]
fn validates_cocoro_archives_and_scenarios() -> Result<()> {
    let root = PathBuf::from(
        std::env::var_os("NVLENS_COCORO_GAME").ok_or(nvlens_core::Error::InvalidFormat)?,
    );
    let cancel = AtomicBool::new(false);
    nvlens_archive::init();
    nvlens_script::init();
    let game = nvlens_engine::identify(&root, &cancel)?.ok_or(nvlens_core::Error::InvalidFormat)?;
    assert_eq!(game.engine, nvlens_engine::Engine::KrkrzHxv4);
    let mut inputs = Vec::new();
    let catalog = Catalog::load();
    for (name, count) in [
        ("bgimage.xp3", 483),
        ("data.xp3", 8811),
        ("fgimage.xp3", 1472),
        ("steam.xp3", 3),
        ("video.xp3", 6),
    ] {
        let path = root.join(name);
        let route = game.route(name).ok_or(nvlens_core::Error::InvalidFormat)?;
        let opened = catalog.open(&path, &route)?;
        assert_eq!(opened.archive.entries().len(), count);
        let entries = opened.archive.entries();
        for index in [0, count / 2, count - 1] {
            assert!(!opened.archive.open_entry(&entries[index])?.is_empty());
        }
        inputs.push((path, route.options));
    }
    let mut recovery = nvlens_archive::krkr::NameRecovery::open(&inputs, &cancel)?;
    while recovery.step(&cancel)? {}
    assert_eq!(recovery.progress().failed, 0);
    assert!(recovery.take_errors().is_empty());
    let mut scenes = 0;
    for (path, names) in recovery.paths() {
        let route = game
            .route_path(&path)
            .ok_or(nvlens_core::Error::InvalidFormat)?;
        let opened = catalog.open(&path, &route)?;
        for (entry, name) in opened.archive.entries().iter().zip(names) {
            if !name.ends_with(".ks.scn") {
                continue;
            }
            let data = opened.archive.open_entry(entry)?;
            let text = nvlens_script::decode_text_as("script/krkr", &data)?
                .ok_or(nvlens_core::Error::InvalidFormat)?;
            assert!(text.starts_with('{'));
            assert!(text.contains("\"scenes\""));
            scenes += 1;
        }
    }
    assert_eq!(scenes, 50);
    println!(
        "Validated 5 archives with 10775 entries, {scenes} PSB scenario previews and {} recovered names",
        recovery.progress().resolved
    );
    Ok(())
}
