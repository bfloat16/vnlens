use super::*;
use std::{collections::BTreeSet, path::PathBuf, sync::atomic::AtomicBool};
use vnlens_core::{ResourceOrigin, ResourceRoute};

#[test]
#[ignore = "Requires installed ToHeart PC; set VNLENS_TAMSOFT_DIR"]
fn installed_game_containers_and_resources() -> Result<()> {
    let root = PathBuf::from(std::env::var_os("VNLENS_TAMSOFT_DIR").ok_or(Error::InvalidFormat)?);
    let game =
        vnlens_engine::identify(&root, &AtomicBool::new(false))?.ok_or(Error::InvalidFormat)?;
    assert_eq!(game.engine, vnlens_engine::Engine::Tamsoft);
    let catalog = Catalog::load();
    let mut dirs = vec![root.clone()];
    let mut archives = 0;
    let mut images = 0;
    let mut decoded = BTreeSet::new();
    let mut audio = BTreeSet::new();
    while let Some(dir) = dirs.pop() {
        for file in std::fs::read_dir(dir)? {
            let path = file?.path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            if !path.extension().is_some_and(|s| {
                s.eq_ignore_ascii_case("cat")
                    || s.eq_ignore_ascii_case("semb")
                    || s.eq_ignore_ascii_case("acb")
                    || s.eq_ignore_ascii_case("awb")
            }) {
                continue;
            }
            let ResourceRoute::Archive(route) = game.route_path(&path)? else {
                // Script banks intentionally stay opaque in the engine route.
                continue;
            };
            let opened = catalog
                .open(&path, &route)
                .inspect_err(|e| eprintln!("{}: {e}", path.display()))?;
            archives += 1;
            let mut pending = vec![opened.archive];
            while let Some(archive) = pending.pop() {
                for entry in archive.entries() {
                    let source = archive.open_entry_source(entry)?;
                    let head = if let Some(source) = &source {
                        source
                            .read_at(
                                0,
                                source.len().min(game.resource_header_len() as u64) as usize,
                            )?
                            .into_owned()
                    } else {
                        let bytes = archive.open_entry(entry)?;
                        bytes[..bytes.len().min(game.resource_header_len())].to_vec()
                    };
                    let route =
                        game.resource_route(&entry.name, ResourceOrigin::Entry(entry.kind), &head);
                    match route {
                        ResourceRoute::Archive(route) if route.tag.ends_with("/tamsoft") => {
                            let opened = if let Some(source) = source {
                                catalog
                                    .open_source(source, &entry.name, &route)?
                                    .ok_or(Error::InvalidFormat)?
                            } else {
                                catalog.open_view(
                                    Arc::new(ArcView::from_bytes(
                                        entry.name.clone().into(),
                                        archive.open_entry(entry)?.into_owned().into(),
                                    )),
                                    &route,
                                )?
                            };
                            pending.push(opened.archive);
                        }
                        ResourceRoute::Image(tag) => {
                            let data = archive.open_entry(entry)?;
                            // Mesh-only floating point lighting textures are outside this adaptation.
                            if data.get(84..88) == Some(&[113, 0, 0, 0]) {
                                continue;
                            }
                            let meta = vnlens_image::metadata_as(tag, &data)
                                .inspect_err(|e| {
                                    eprintln!(
                                        "{} > {} at {:x}: {e}",
                                        path.display(),
                                        entry.name,
                                        entry.offset
                                    )
                                })?
                                .ok_or(Error::InvalidFormat)?;
                            assert!(meta.width != 0 && meta.height != 0);
                            // Decode a representative of each native pixel encoding and layout;
                            // every image still validates its complete surface directory.
                            let key = (
                                data[84..88].to_vec(),
                                if data.get(84..88) == Some(b"DX10") {
                                    data.get(128..132).unwrap_or_default().to_vec()
                                } else {
                                    Vec::new()
                                },
                                data[24..32].to_vec(),
                                data[112..116].to_vec(),
                            );
                            if decoded.insert(key) {
                                vnlens_image::decode_as(tag, &data).inspect_err(|e| {
                                    eprintln!(
                                        "{} > {} at {:x}: {e}",
                                        path.display(),
                                        entry.name,
                                        entry.offset
                                    )
                                })?;
                            }
                            images += 1;
                        }
                        ResourceRoute::Audio(tag)
                            if audio.insert((tag.to_string(), path.clone())) =>
                        {
                            let data = archive.open_entry(entry)?;
                            let pcm = vnlens_audio::decode_as(tag, &data)?;
                            assert!(!pcm.samples.is_empty());
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    assert!(archives > 0 && images > 0 && !audio.is_empty());
    eprintln!(
        "Tamsoft: {archives} disk containers, {images} images, {} image layouts decoded, {} audio bank samples",
        decoded.len(),
        audio.len()
    );
    Ok(())
}
