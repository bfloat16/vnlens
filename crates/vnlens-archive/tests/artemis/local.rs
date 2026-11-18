use super::*;

/// Set VNLENS_ARTEMIS_DIR to the local WorldActorGB installation and run
/// cargo test -p vnlens-archive artemis_game -- --ignored --nocapture.
#[test]
#[ignore = "Requires the local Artemis game; no restricted assets are embedded"]
fn artemis_game_mounts_companions_and_decodes_native_scripts_and_media() -> Result<()> {
    let root = PathBuf::from(
        std::env::var_os("VNLENS_ARTEMIS_DIR")
            .ok_or_else(|| Error::Unsupported("Set VNLENS_ARTEMIS_DIR".into()))?,
    );
    let cancel = AtomicBool::new(false);
    let game = vnlens_engine::identify(&root, &cancel)?.ok_or(Error::InvalidFormat)?;
    assert_eq!(game.engine, vnlens_engine::Engine::Artemis);
    let files = game
        .files
        .read_dir(&root)?
        .into_iter()
        .filter_map(|f| (!f.metadata.directory).then_some(f.path))
        .collect::<Vec<_>>();
    let sets = game.archive_sets(&files);
    let set = sets
        .iter()
        .find(|s| {
            s.primary
                .file_name()
                .is_some_and(|s| s == "WorldActorGB.pfs")
        })
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(set.members.len(), 3);
    let vnlens_core::ResourceRoute::Archive(route) = game.route_path(&set.primary)? else {
        return Err(Error::InvalidFormat);
    };
    let archive = vnlens_core::Catalog::load()
        .open_view(Arc::new(game.files.open(&set.primary)?), &route)?
        .archive;
    let mut scripts = 0;
    let mut asb = 0;
    let mut images = std::collections::BTreeSet::new();
    let mut audio = false;
    for entry in archive.entries() {
        let route = game.resource_route(
            &entry.name,
            vnlens_core::ResourceOrigin::Entry(entry.kind),
            &[],
        );
        match route {
            vnlens_core::ResourceRoute::Script(tag) => {
                let bytes = archive.open_entry(entry)?;
                let ir = vnlens_script::disassemble_cancellable_as(
                    tag,
                    &bytes,
                    None,
                    game.resource_options(),
                    &cancel,
                )?;
                if let Some(ir) = ir {
                    assert_eq!(ir.sections[0].raw, &*bytes);
                    assert!(!ir.instructions.is_empty());
                    asb += 1;
                } else {
                    assert!(vnlens_script::decode_text_as(tag, &bytes)?.is_some());
                }
                scripts += 1;
            }
            vnlens_core::ResourceRoute::Image(tag) => {
                let ext = entry.name.rsplit('.').next().unwrap_or("");
                if images.insert(ext.to_owned()) {
                    let bytes = archive.open_entry(entry)?;
                    let meta =
                        vnlens_image::metadata_as(tag, &bytes)?.ok_or(Error::InvalidFormat)?;
                    assert!(meta.width > 0 && meta.height > 0);
                    let image = vnlens_image::decode_as(tag, &bytes)?;
                    assert_eq!(
                        (image.meta.width, image.meta.height),
                        (meta.width, meta.height)
                    );
                }
            }
            vnlens_core::ResourceRoute::Media { audio: tag, .. }
                if entry.name.ends_with(".ogg") && !audio =>
            {
                let bytes = archive.open_entry(entry)?;
                let decoded = vnlens_audio::decode_as(tag, &bytes)?;
                assert!(
                    decoded.meta.sample_rate > 0
                        && decoded.meta.channels > 0
                        && !decoded.samples.is_empty()
                );
                audio = true;
            }
            _ => {}
        }
    }
    assert_eq!(asb, 3);
    assert!(audio && images.contains("png") && images.contains("jpg"));
    eprintln!(
        "Artemis: {} merged entries, {scripts} scripts ({asb} ASB), PNG/JPEG pixels and Ogg PCM verified",
        archive.entries().len()
    );
    Ok(())
}
