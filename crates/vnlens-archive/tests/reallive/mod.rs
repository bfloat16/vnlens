use super::*;
use vnlens_io::BinaryWriter;

fn view(bytes: Vec<u8>) -> Arc<ArcView> {
    Arc::new(ArcView::from_bytes("Seen.txt".into(), bytes.into()))
}
fn fixture() -> Vec<u8> {
    let mut bytes = vec![0; 80008];
    for (id, offset) in [(42, 80000), (9999, 80004)] {
        BinaryWriter::u32_le(offset, &mut bytes[id * 8..]);
        BinaryWriter::u32_le(4, &mut bytes[id * 8 + 4..]);
    }
    bytes[80000..].copy_from_slice(b"goodBAD!");
    bytes
}

#[test]
fn index_holes_lazy_payloads_and_original_storage() -> Result<()> {
    let view = view(fixture());
    let archive = Seen.open(&view, &ArchiveOptions::default())?;
    assert_eq!(
        archive
            .entries()
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>(),
        ["Seen0042.txt", "Seen9999.txt"]
    );
    let entry = &archive.entries()[0];
    assert!(matches!(archive.open_entry(entry)?, Cow::Borrowed(b"good")));
    assert_eq!(archive.open_entry_raw(entry)?.as_ref(), b"good");
    // No compiler headers or keys are required to mount a valid index.
    // The corrupt, unrequested second scene cannot affect this first read.
    let mut forged = entry.clone();
    forged.offset += 1;
    assert!(matches!(
        archive.open_entry(&forged),
        Err(Error::Corrupt { .. })
    ));
    Ok(())
}

#[test]
fn rejects_truncated_index_storage_and_overlap() {
    for length in [0, 7, 79999, 80007] {
        let mut bytes = fixture();
        bytes.truncate(length);
        assert!(
            matches!(Seen.open(&view(bytes), &ArchiveOptions::default()), Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof)
        );
    }
    let mut bytes = fixture();
    BinaryWriter::u32_le(79999, &mut bytes[42 * 8..]);
    assert!(matches!(
        Seen.open(&view(bytes), &ArchiveOptions::default()),
        Err(Error::Corrupt { .. })
    ));
}

fn collect(
    path: &std::path::Path,
    files: &mut std::collections::BTreeMap<String, Vec<std::path::PathBuf>>,
) -> Result<()> {
    for file in std::fs::read_dir(path)? {
        let file = file?;
        if file.file_type()?.is_dir() {
            collect(&file.path(), files)?;
        } else if let Some(ext) = file.path().extension().and_then(|e| e.to_str()) {
            files
                .entry(ext.to_ascii_lowercase())
                .or_default()
                .push(file.path());
        }
    }
    Ok(())
}
fn samples<T>(items: &[T]) -> Vec<&T> {
    if items.is_empty() {
        return Vec::new();
    }
    let mut indices = vec![0, items.len() / 2, items.len() - 1];
    indices.dedup();
    indices.into_iter().map(|i| &items[i]).collect()
}
fn audio(tag: &str, data: &[u8]) -> Result<()> {
    let meta = vnlens_audio::metadata_as(tag, data)?.ok_or(Error::InvalidFormat)?;
    let pcm = vnlens_audio::decode_as(tag, data)?;
    assert_eq!(pcm.meta.channels, meta.channels);
    assert_eq!(pcm.meta.sample_rate, meta.sample_rate);
    assert!(!pcm.samples.is_empty());
    assert!(pcm.samples.iter().all(|s| s.is_finite()));
    assert!(pcm.samples.len().is_multiple_of(usize::from(meta.channels)));
    if let Some(frames) = meta.frames {
        assert_eq!(pcm.samples.len() as u64 / u64::from(meta.channels), frames);
    }
    Ok(())
}

#[test]
#[ignore = "Requires four licensed installations under VNLENS_REALLIVE_SAMPLES; run cargo test -p vnlens-archive reallive_local -- --ignored --nocapture"]
fn reallive_local_games() -> Result<()> {
    use std::{collections::BTreeMap, path::PathBuf, sync::atomic::AtomicBool};
    use vnlens_core::{Catalog, ResourceOrigin, ResourceRoute};
    let root = std::env::var_os("VNLENS_REALLIVE_SAMPLES")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("E:/VN/_Engine/RealLive"));
    let cancel = AtomicBool::new(false);
    let catalog = Catalog::load();
    for (name, scenes) in [
        ("Hinasawa Tomoka no Zettai Joousei", 113),
        (
            "Kareshi Inai Reki = Nenrei Ja, Doushite Ikenai no yo! ~Sei Torea Gakuen Ren'ai Kinshi Rei~",
            299,
        ),
        ("Niizuma Shino", 63),
        ("Princess Heart Link ~Kenki-tachi no Enbu~", 202),
    ] {
        let path = root.join(name);
        let game = vnlens_engine::identify(&path, &cancel)?.ok_or(Error::InvalidFormat)?;
        assert_eq!(game.engine, vnlens_engine::Engine::RealLive);
        let ResourceRoute::Archive(route) =
            game.resource_route("Seen.txt", ResourceOrigin::File, &[])
        else {
            return Err(Error::InvalidFormat);
        };
        let opened =
            catalog.open_view(Arc::new(game.files.open(&path.join("Seen.txt"))?), &route)?;
        assert_eq!(opened.format_tag, "seen/reallive");
        assert_eq!(opened.archive.entries().len(), scenes);
        for entry in opened.archive.entries() {
            let data = opened.archive.open_entry(entry)?;
            let ResourceRoute::Script(tag) = game.resource_route(
                &entry.name,
                ResourceOrigin::Entry(entry.kind),
                &data[..data.len().min(16)],
            ) else {
                return Err(Error::InvalidFormat);
            };
            let ir = vnlens_script::disassemble_with_options_as(tag, &data, None, &route.options)?
                .ok_or(Error::InvalidFormat)?;
            assert!(!ir.instructions.is_empty());
        }
        let mut files = BTreeMap::new();
        collect(&path, &mut files)?;
        for paths in files.values_mut() {
            paths.sort();
        }
        let mut counts = [0; 4];
        for ext in ["g00", "nwa", "gan", "ovk", "nwk"] {
            let Some(paths) = files.get(ext) else {
                continue;
            };
            for path in samples(paths) {
                let view = Arc::new(game.files.open(path)?);
                let resource =
                    game.resource_route(&path.to_string_lossy(), ResourceOrigin::File, &[]);
                match resource {
                    ResourceRoute::Image(tag) => {
                        let data = view.slice(0, view.len())?;
                        let meta =
                            vnlens_image::metadata_as(tag, data)?.ok_or(Error::InvalidFormat)?;
                        let frames = vnlens_image::frame_count_as(tag, data)?;
                        assert!(frames > 0 && meta.width > 0 && meta.height > 0);
                        for frame in samples(&(0..frames).collect::<Vec<_>>()) {
                            let image = vnlens_image::decode_frame_as(tag, data, *frame)?;
                            let pixels = match &image.pixels {
                                vnlens_image::PixelBuffer::Bgra8(bytes)
                                | vnlens_image::PixelBuffer::Rgba8(bytes) => bytes,
                                _ => return Err(Error::InvalidFormat),
                            };
                            assert_eq!(pixels.len(), image.meta.rgba_size()?);
                            counts[0] += 1;
                        }
                    }
                    ResourceRoute::Audio(tag) => {
                        audio(tag, view.slice(0, view.len())?)?;
                        counts[1] += 1;
                    }
                    ResourceRoute::Script(tag) => {
                        let ir =
                            vnlens_script::disassemble_as(tag, view.slice(0, view.len())?, None)?
                                .ok_or(Error::InvalidFormat)?;
                        assert!(!ir.instructions.is_empty());
                        counts[2] += 1;
                    }
                    ResourceRoute::Archive(route) => {
                        let voice = catalog.open_view(view, &route)?;
                        assert!(!voice.archive.entries().is_empty());
                        for entry in samples(voice.archive.entries()) {
                            let data = voice.archive.open_entry(entry)?;
                            let tag = match game.resource_route(
                                &entry.name,
                                ResourceOrigin::Entry(entry.kind),
                                &data[..data.len().min(16)],
                            ) {
                                ResourceRoute::Audio(tag)
                                | ResourceRoute::Media { audio: tag, .. } => tag,
                                _ => return Err(Error::InvalidFormat),
                            };
                            audio(tag, &data)?;
                            counts[3] += 1;
                        }
                    }
                    _ => return Err(Error::InvalidFormat),
                }
            }
        }
        assert!(counts[0] > 0 && counts[1] > 0 && counts[3] > 0);
        println!(
            "Verified {name}: {scenes} scripts; {} image frames, {} NWA, {} GAN, {} voice entries",
            counts[0], counts[1], counts[2], counts[3]
        );
    }
    Ok(())
}
