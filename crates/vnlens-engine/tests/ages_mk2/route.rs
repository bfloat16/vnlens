use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin, ResourceRoute, Secret};

fn identified() -> Identification {
    Identification {
        files: Default::default(),
        root: Default::default(),
        engine: Engine::AgesMk2,
        evidence: "Fixture".into(),
        options: ArchiveOptions::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    }
}

#[test]
fn foreign_native_names_and_ordinary_media_keep_their_scoped_routes() {
    let game = identified();
    for name in [
        "cg.MGR",
        "scenario.MSC",
        "cg.G00",
        "voice.NWA",
        "scene.SS",
        "cg._bg",
        "voice.BW",
        "scene._bp",
        "cg.LVG",
        "cg.DLT",
        "scene.RLD",
        "cg.YCG",
        "scene.YBN",
        "movie.YMV",
        "cg.PNA",
        "scene.WS2",
        "cg.DWQ",
        "voice.VAW",
        "scene.SPT",
        "scene.LSF",
        "cg.cr6ti",
        "voice.oor",
        "cg.TLG",
        "scene.KS",
    ] {
        assert_eq!(
            game.resource_route(name, ResourceOrigin::File, &[]),
            ResourceRoute::Other(ResourceKind::Unknown)
        );
    }
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

#[test]
fn fpd_routes_select_matching_resident_or_obb_scramble_keys() {
    let mut game = identified();
    game.options
        .keys
        .insert("resident", Secret::new(b"resident-key".to_vec()));
    game.options
        .keys
        .insert("obb", Secret::new(b"obb-key".to_vec()));
    let resident = match game.resource_route("resident/pack.fpd", ResourceOrigin::File, &[]) {
        ResourceRoute::Archive(route) => Some(*route),
        _ => None,
    };
    assert!(
        matches!(resident, Some(ArchiveRoute { tag: "fpd", options }) if options.keys["scramble"].bytes() == b"resident-key")
    );
    let obb = match game.resource_route("obb/main.1.dat", ResourceOrigin::File, &[]) {
        ResourceRoute::Archive(route) => Some(*route),
        _ => None,
    };
    assert!(
        matches!(obb, Some(ArchiveRoute { tag: "fpd", options }) if options.keys["scramble"].bytes() == b"obb-key")
    );
}
