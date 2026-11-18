use super::*;
use std::{collections::BTreeSet, sync::atomic::AtomicBool};
use vnlens_core::{Catalog, ResourceOrigin, ResourceRoute};

#[test]
#[ignore = "Requires local Mizuiro or Gin'iro Complete Edition; set VNLENS_NSCRIPTER_DIR"]
fn installed_game_archives_and_resources() -> Result<()> {
    let root = std::path::PathBuf::from(
        std::env::var_os("VNLENS_NSCRIPTER_DIR").ok_or(Error::InvalidFormat)?,
    );
    let game =
        vnlens_engine::identify(&root, &AtomicBool::new(false))?.ok_or(Error::InvalidFormat)?;
    assert_eq!(game.engine, vnlens_engine::Engine::NScripter);
    let path = root.join("nscript.dat");
    let data = std::fs::read(path)?;
    let decoded = vnlens_script::decode_as("nscript/nscripter", &data, game.resource_options())?;
    let text = vnlens_script::decode_text_as("nscript/nscripter", &decoded)?
        .ok_or(Error::InvalidFormat)?;
    assert!(text.contains("*define") && text.contains("*start"));
    let catalog = Catalog::load();
    let mut paths = std::fs::read_dir(&root)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.retain(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("nsa")));
    paths.sort();
    assert_eq!(paths.len(), 10);
    let mut seen = BTreeSet::new();
    for path in paths {
        let ResourceRoute::Archive(route) = game.route_path(&path)? else {
            return Err(Error::InvalidFormat);
        };
        let opened = catalog.open(&path, &route)?;
        let mut compressed = 0;
        for entry in opened.archive.entries() {
            compressed += usize::from(entry.packed.is_some());
            let ext = entry
                .name
                .rsplit('.')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let route = game.resource_route(&entry.name, ResourceOrigin::Entry(entry.kind), &[]);
            if entry.packed.is_none() && !seen.insert(ext) {
                continue;
            }
            let bytes = opened
                .archive
                .open_entry(entry)
                .inspect_err(|e| eprintln!("{} > {}: {e}", path.display(), entry.name))?;
            match route {
                ResourceRoute::Image(tag) => {
                    vnlens_image::decode_as(tag, &bytes)?;
                }
                ResourceRoute::Audio(tag) => {
                    let pcm = vnlens_audio::decode_as(tag, &bytes)?;
                    assert!(!pcm.samples.is_empty());
                }
                _ => {}
            }
        }
        eprintln!(
            "{}: {} entries ({} compressed)",
            path.display(),
            opened.archive.entries().len(),
            compressed
        );
    }
    assert!(seen.contains("mp3"));
    Ok(())
}
