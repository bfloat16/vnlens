use super::*;
use std::sync::atomic::AtomicBool;
use vnlens_core::{Catalog, ResourceRoute};

#[test]
#[ignore = "Requires a local SHIELD-9 Reboot installation; set VNLENS_SHIELD9_DIR"]
fn shield9_archives_mount() -> Result<()> {
    let root = PathBuf::from(std::env::var_os("VNLENS_SHIELD9_DIR").ok_or(Error::InvalidFormat)?);
    let cancelled = AtomicBool::new(false);
    let game = vnlens_engine::identify(&root, &cancelled)?.ok_or(Error::InvalidFormat)?;
    eprintln!("Engine: {:?}; evidence: {}", game.engine, game.evidence);
    let mut paths = fs::read_dir(&root)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.retain(|path| {
        path.extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("xp3"))
    });
    paths.sort();
    assert_eq!(paths.len(), 5);
    let catalog = Catalog::load();
    for path in paths {
        let ResourceRoute::Archive(route) = game.route_path(&path)? else {
            return Err(Error::InvalidFormat);
        };
        let opened = catalog.open(&path, &route).inspect_err(|error| {
            eprintln!("{}: {error}", path.display());
        })?;
        eprintln!(
            "{}: {} entries",
            path.display(),
            opened.archive.entries().len()
        );
        let expected = match path.file_stem().and_then(|stem| stem.to_str()) {
            Some("bgimage") => 269,
            Some("data") => 2560,
            Some("evimage") => 444,
            Some("fgimage") => 2880,
            Some("voice") => 17638,
            _ => return Err(Error::InvalidFormat),
        };
        assert_eq!(opened.archive.entries().len(), expected);
        assert!(opened.archive.entries().iter().all(|entry| {
            !entry
                .name
                .starts_with("$$$ This is a protected archive. $$$ ")
        }));
        let entry = opened
            .archive
            .entries()
            .first()
            .ok_or(Error::InvalidFormat)?;
        let data = opened.archive.open_entry(entry)?;
        assert!(!data.is_empty());
        let source = opened
            .archive
            .open_entry_source(entry)?
            .ok_or(Error::InvalidFormat)?;
        assert_eq!(source.read_at(0, data.len())?.as_ref(), data.as_ref());
    }
    Ok(())
}
