//! Set NVLENS_SYSTEMNNN_GAME to an owned Extravaganza Mushigurui Hen install.
//! cargo test --release -p nvlens-archive --test systemnnn_game -- --ignored --nocapture
//! All processing is in memory; the game and GUI are never launched.
use nvlens_core::{Catalog, Error, ResourceResolver, Result};
use nvlens_crypto::hash::md5;
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

struct Resources(PathBuf);
impl ResourceResolver for Resources {
    fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.0.join(name)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
fn files(path: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            files(&entry.path(), output)?;
        } else if entry.file_type()?.is_file() {
            output.push(entry.path());
        }
    }
    Ok(())
}
#[test]
#[ignore = "Requires NVLENS_SYSTEMNNN_GAME pointing to an owned game installation"]
fn validates_extravaganza() -> Result<()> {
    let root =
        PathBuf::from(std::env::var_os("NVLENS_SYSTEMNNN_GAME").ok_or(Error::InvalidFormat)?);
    nvlens_archive::init();
    nvlens_image::init();
    nvlens_audio::init();
    nvlens_script::init();
    let game =
        nvlens_engine::identify(&root, &AtomicBool::new(false))?.ok_or(Error::InvalidFormat)?;
    assert_eq!(game.engine, nvlens_engine::Engine::SystemNnn);
    let catalog = Catalog::load();
    for (name, count, images) in [
        ("dwq/bg0.gpk", 24, true),
        ("dwq/ev0.gpk", 236, true),
        ("dwq/sc0.gpk", 31, true),
        ("dwq/sm0.gpk", 243, true),
        ("dwq/sys0.gpk", 267, true),
        ("dwq/ta0.gpk", 500, true),
        ("cdvaw/aa.vpk", 1754, false),
        ("cdvaw/bb.vpk", 1201, false),
        ("cdvaw/cc.vpk", 508, false),
        ("cdvaw/dd.vpk", 1065, false),
        ("cdvaw/ee.vpk", 591, false),
        ("cdvaw/ff.vpk", 150, false),
        ("cdvaw/gg.vpk", 304, false),
        ("cdvaw/hh.vpk", 138, false),
        ("cdvaw/ii.vpk", 335, false),
    ] {
        let route = game.route(name).ok_or(Error::InvalidFormat)?;
        let opened = catalog.open(root.join(name), &route)?;
        let archive = opened.archive;
        assert_eq!(archive.entries().len(), count);
        let mut content_hashes = Vec::new();
        let mut decoded_hashes = Vec::new();
        for (i, entry) in archive.entries().iter().enumerate() {
            let bytes = archive.open_entry(entry)?;
            content_hashes.extend(md5::digest(&bytes));
            if images {
                let image = nvlens_image::decode(&bytes)
                    .inspect_err(|e| eprintln!("{name}: {}: {e}", entry.name))?
                    .ok_or(Error::InvalidFormat)?;
                match image.pixels {
                    nvlens_image::PixelBuffer::Rgba8(pixels) => {
                        assert_eq!(pixels.len(), image.meta.rgba_size()?);
                        decoded_hashes.extend(md5::digest(&pixels));
                    }
                    _ => return Err(Error::Unsupported("Unexpected sample pixels".into())),
                }
            } else {
                let meta = nvlens_audio::metadata(&bytes)
                    .inspect_err(|e| eprintln!("{name}: {}: {e}", entry.name))?
                    .ok_or(Error::InvalidFormat)?;
                assert_eq!(meta.channels, 1);
                assert_eq!(meta.sample_rate, 44100);
                // Both 16- and 40-byte fmt variants occur among these records.
                if i < 3 || i % 97 == 0 {
                    let pcm = nvlens_audio::decode(&bytes)?.ok_or(Error::InvalidFormat)?;
                    assert!(pcm.samples.iter().all(|v| v.is_finite()));
                    assert_eq!(pcm.meta.frames, Some(pcm.samples.len() as u64));
                }
            }
        }
        // Golden RGBA aggregates independently verified with Pillow and the
        // documented sequential BMP palette/row layout.
        let expected_pixels = match name {
            "dwq/bg0.gpk" => Some([
                0x72, 0xfd, 0x8c, 0xff, 0x93, 0xf9, 0xa3, 0x63, 0x40, 0x65, 0xff, 0xc4, 0xca, 0xb3,
                0x02, 0xdf,
            ]),
            "dwq/ev0.gpk" => Some([
                0xb6, 0xf4, 0xef, 0x77, 0x2f, 0x56, 0x34, 0x5f, 0x53, 0x71, 0x1b, 0x76, 0xd3, 0xf6,
                0x71, 0x70,
            ]),
            "dwq/sc0.gpk" => Some([
                0x52, 0xad, 0xe3, 0x6a, 0xbd, 0xe5, 0x25, 0xbc, 0x4a, 0x59, 0xfd, 0x19, 0xeb, 0x14,
                0x5b, 0x09,
            ]),
            "dwq/sm0.gpk" => Some([
                0x79, 0x3b, 0xd3, 0x3f, 0xc0, 0x3f, 0x43, 0xd9, 0xba, 0x59, 0x84, 0xf5, 0x65, 0xb5,
                0xbd, 0x92,
            ]),
            "dwq/sys0.gpk" => Some([
                0xa7, 0xb6, 0x56, 0x33, 0xec, 0x59, 0x8d, 0xe4, 0xa4, 0x5e, 0x34, 0xfb, 0xc6, 0xfa,
                0x1a, 0x19,
            ]),
            "dwq/ta0.gpk" => Some([
                0x3a, 0x53, 0xb7, 0xf8, 0x52, 0x3e, 0x0d, 0xe3, 0x7d, 0xae, 0x9e, 0x86, 0x46, 0xb7,
                0xd8, 0x9d,
            ]),
            _ => None,
        };
        if let Some(expected) = expected_pixels {
            assert_eq!(md5::digest(&decoded_hashes), expected, "{name}");
        }
        println!(
            "{name}: {count}, content {:02x?}, pixels {:02x?}",
            md5::digest(&content_hashes),
            md5::digest(&decoded_hashes)
        );
    }
    let mut paths = Vec::new();
    files(&root, &mut paths)?;
    paths.sort();
    let mut counts = [0usize; 3];
    let mut damaged_audio = Vec::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(Error::InvalidFormat)?;
        if let Some(tag) = game.script_format_for(name) {
            let raw = std::fs::read(&path)?;
            let bytes = nvlens_script::decode_as(tag, &raw, game.resource_options())?;
            if tag == "spt/systemnnn" {
                let resolver = Resources(path.parent().ok_or(Error::InvalidFormat)?.into());
                let script = nvlens_script::disassemble_as(tag, &bytes, Some(&resolver))
                    .inspect_err(|e| eprintln!("{name}: {e}"))?
                    .ok_or(Error::InvalidFormat)?;
                let texts: Vec<_> = script
                    .instructions
                    .iter()
                    .flat_map(|i| &i.args)
                    .filter_map(|a| match &a.value {
                        nvlens_script::ir::Value::Text(s) => Some(s.as_str()),
                        _ => None,
                    })
                    .collect();
                println!(
                    "{name}: {} instructions, {} strings, text {:02x?}",
                    script.instructions.len(),
                    texts.len(),
                    md5::digest(texts.join("\n").as_bytes())
                );
                assert_eq!(script.sections[0].raw, bytes.as_ref());
                counts[0] += 1;
            } else {
                assert!(
                    nvlens_script::decode_text_as(tag, &bytes)
                        .inspect_err(|e| eprintln!("{name}: {e}"))?
                        .is_some()
                );
                counts[1] += 1;
            }
        } else if matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("vaw" | "wgq")
        ) {
            let bytes = std::fs::read(&path)?;
            match nvlens_audio::decode(&bytes) {
                Ok(Some(pcm)) => assert!(pcm.samples.iter().all(|v| v.is_finite())),
                Err(Error::Corrupt { .. } | Error::Io(_)) => {
                    damaged_audio.push(name.to_owned());
                    // This owned installation has a truncated PCM file:
                    // RIFF declares 25,314,280 bytes, but only 4,096 remain.
                    assert_eq!(bytes.len(), 4160);
                    assert_eq!(nvlens_io::BinaryReader::u32_le(&bytes[68..]), 25_314_272);
                }
                other => {
                    return Err(Error::Unsupported(format!(
                        "Unexpected audio result for {name}: {other:?}"
                    )));
                }
            }
            counts[2] += 1;
        }
    }
    assert_eq!(counts, [7, 46, 408]);
    assert_eq!(damaged_audio, ["so02.vaw"]);
    println!("Loose resources: {counts:?}");
    Ok(())
}
