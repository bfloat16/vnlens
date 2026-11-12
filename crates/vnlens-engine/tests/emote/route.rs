use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ArchiveOptions, ResourceOrigin, ResourceRoute};

fn identified(engine: Engine) -> Identification {
    Identification {
        files: Default::default(),
        root: PathBuf::from("game"),
        engine,
        evidence: "Fixture".into(),
        options: ArchiveOptions::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    }
}

fn files(names: &[&str]) -> Vec<PathBuf> {
    names
        .iter()
        .map(|name| PathBuf::from("game").join(name))
        .collect()
}

#[test]
fn emote_uses_the_same_body_priority_as_the_reader() {
    let mut game = identified(Engine::Krkr);
    let paths = files(&[
        "sample_info.psb.m",
        "sample_body.bin",
        "samplebody.bin",
        "sample.bin",
    ]);
    assert!(game.archive_sets(&paths).is_empty());
    game.middleware = vec![&ROUTER];
    let sets = game.archive_sets(&paths);
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].members, paths[..2]);
}

#[test]
fn psb_shell_routes_stay_with_the_identified_middleware() {
    let mut configured = identified(Engine::AgesMk2);
    assert!(!configured.supports_psb());
    configured.middleware = vec![&ROUTER];
    assert!(configured.supports_psb());
    for name in [
        "texture.psz",
        "texture.mdf",
        "texture.mzs",
        "texture.pimg",
        "motion.mmo",
    ] {
        assert!(
            matches!(configured.resource_route(name, ResourceOrigin::File, &[]), ResourceRoute::Archive(route) if route.tag == "psb")
        );
    }
    for name in [
        "pack_info.psb.psz",
        "pack_info.psb.mdf",
        "pack_info.psb.mzs",
    ] {
        assert!(
            matches!(configured.resource_route(name, ResourceOrigin::File, &[]), ResourceRoute::Archive(route) if route.tag == "psb/archive-info")
        );
    }
}
