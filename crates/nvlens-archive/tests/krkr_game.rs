//! Set NVLENS_KRKR_GAME to a licensed Ousama Ren'ai installation and run:
//! cargo test --release -p nvlens-archive --test krkr_game -- --ignored --nocapture
//! Reads and validates resources in memory; never runs plugins or writes samples.
use nvlens_core::{Catalog, Error, Result};
use std::{collections::BTreeMap, path::PathBuf, sync::atomic::AtomicBool};

#[test]
#[ignore = "Requires NVLENS_KRKR_GAME pointing to a licensed Ousama Ren'ai installation"]
fn validates_ousama_archives_and_resources() -> Result<()> {
    let root = PathBuf::from(std::env::var_os("NVLENS_KRKR_GAME").ok_or(Error::InvalidFormat)?);
    nvlens_archive::init();
    nvlens_image::init();
    nvlens_audio::init();
    nvlens_script::init();
    let game =
        nvlens_engine::identify(&root, &AtomicBool::new(false))?.ok_or(Error::InvalidFormat)?;
    assert_eq!(game.engine, nvlens_engine::Engine::Krkr);
    assert_eq!(game.resource_options().numbers.get("xp3_xor31"), Some(&1));
    assert!(!game.resource_options().numbers.contains_key("hxv4"));
    let catalog = Catalog::load();
    for (name, count) in [
        ("bgimage.xp3", 161),
        ("bgm.xp3", 29),
        ("data.xp3", 1058),
        ("evimage.xp3", 699),
        ("stimage.xp3", 3091),
        ("voice.xp3", 12885),
    ] {
        let route = game.route(name).ok_or(Error::InvalidFormat)?;
        assert_eq!(route.tag, "xp3/krkr");
        let opened = catalog.open(root.join(name), &route)?;
        let archive = opened.archive;
        assert_eq!(archive.entries().len(), count);
        let mut kinds = BTreeMap::<String, usize>::new();
        let mut contents = Vec::new();
        let mut pixels = Vec::new();
        let mut decoded_audio = false;
        for entry in archive.entries() {
            let bytes = archive
                .open_entry(entry)
                .inspect_err(|e| eprintln!("{name}: {}: {e}", entry.name))?;
            contents.extend(nvlens_crypto::hash::md5::digest(&bytes));
            let ext = entry.name.rsplit('.').next().unwrap_or("");
            *kinds.entry(ext.into()).or_default() += 1;
            match ext {
                "png" | "tlg" => {
                    let image = nvlens_image::decode(&bytes)
                        .inspect_err(|e| eprintln!("{name}: {}: {e}", entry.name))?
                        .ok_or(Error::InvalidFormat)?;
                    let mut expected = image.meta.rgba_size()?;
                    let data = match image.pixels {
                        nvlens_image::PixelBuffer::Bgra8(data) => data,
                        nvlens_image::PixelBuffer::Rgba8(mut data) => {
                            nvlens_image::swap_red_blue(&mut data);
                            data
                        }
                        nvlens_image::PixelBuffer::Rgba16(words) => {
                            assert_eq!(words.len(), expected);
                            expected *= 2;
                            let mut bytes = vec![0; expected];
                            for (word, bytes) in words.iter().zip(bytes.as_chunks_mut::<2>().0) {
                                nvlens_io::BinaryWriter::u16_le(*word, bytes);
                            }
                            bytes
                        }
                        _ => {
                            return Err(Error::Unsupported("Unexpected sample pixel depth".into()));
                        }
                    };
                    assert_eq!(data.len(), expected);
                    pixels.extend(nvlens_crypto::hash::md5::digest(&data));
                }
                "ogg" | "opus" => {
                    let meta = nvlens_audio::metadata(&bytes)?.ok_or(Error::InvalidFormat)?;
                    assert!(meta.sample_rate > 0 && meta.channels > 0);
                    if !decoded_audio {
                        let pcm = nvlens_audio::decode(&bytes)?.ok_or(Error::InvalidFormat)?;
                        assert_eq!(pcm.meta.frames, meta.frames);
                        assert!(pcm.samples.iter().all(|s| s.is_finite()));
                        decoded_audio = true;
                    }
                }
                "tjs" | "ks" | "asd" => {
                    assert_eq!(game.script_format_for(&entry.name), Some("script/krkr"));
                    if let Some(text) = nvlens_script::decode_text_as("script/krkr", &bytes)? {
                        assert!(!text.is_empty());
                    } else {
                        assert!(std::str::from_utf8(&bytes).is_ok(), "{}", entry.name);
                    }
                }
                "txt" | "ttf" => {}
                _ => {
                    return Err(Error::Unsupported(format!(
                        "Unexpected sample resource: {}",
                        entry.name
                    )));
                }
            }
        }
        println!(
            "{name}: {count} resources {kinds:?}; contents {:02x?}; pixels {:02x?}",
            nvlens_crypto::hash::md5::digest(&contents),
            nvlens_crypto::hash::md5::digest(&pixels)
        );
    }
    Ok(())
}
