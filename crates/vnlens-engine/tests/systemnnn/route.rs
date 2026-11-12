use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin, ResourceRoute};

fn identified() -> Identification {
    Identification {
        files: Default::default(),
        root: PathBuf::from("game"),
        engine: Engine::SystemNnn,
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
fn systemnnn_pairs_gpk_gtb_and_vpk_vtb() {
    let paths = files(&[
        "BG.GPK",
        "BG.GTB",
        "voice.vpk",
        "voice.vtb",
        "orphan.gtb",
        "other/BG.GTB",
    ]);
    let sets = identified().archive_sets(&paths);
    assert_eq!(sets.len(), 2);
    assert_eq!(sets[0].primary, paths[0]);
    assert_eq!(sets[0].members, paths[..2]);
    assert_eq!(sets[1].members, paths[2..4]);
}

#[test]
fn native_names_and_dwq_header_precedence() {
    let game = identified();
    assert_eq!(
        game.resource_route("cg.DWQ", ResourceOrigin::File, &[]),
        ResourceRoute::Image("dwq/systemnnn")
    );
    assert_eq!(
        game.resource_route("voice.VAW", ResourceOrigin::File, &[]),
        ResourceRoute::Audio("vaw/systemnnn")
    );
    assert_eq!(
        game.resource_route("scene.SPT", ResourceOrigin::File, &[]),
        ResourceRoute::Script("spt/systemnnn")
    );
    assert_eq!(
        game.resource_route("0000", ResourceOrigin::File, b"BMP "),
        ResourceRoute::Image("dwq/systemnnn")
    );
    assert_eq!(
        game.resource_route("cg.png", ResourceOrigin::File, &[]),
        ResourceRoute::Image("image/standard")
    );
    assert!(matches!(
        game.resource_route("voice.ogg", ResourceOrigin::File, &[]),
        ResourceRoute::Media { .. }
    ));
    assert_eq!(
        game.resource_route("folder.msc/unknown", ResourceOrigin::File, &[]),
        ResourceRoute::Other(ResourceKind::Unknown)
    );
}
