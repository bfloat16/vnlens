use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin, ResourceRoute};

fn identified() -> Identification {
    Identification {
        files: Default::default(),
        root: PathBuf::from("game"),
        engine: Engine::Rugp,
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
fn rugp_collects_rio_index_and_volumes() {
    let paths = files(&[
        "game.RIO",
        "game.RIO.ici",
        "game.RIO.002",
        "game.RIO.003",
        "game.RIO.ruo",
        "game.RIO.004.bak",
        "other.RIO.002",
    ]);
    let sets = identified().archive_sets(&paths);
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].primary, paths[0]);
    assert_eq!(sets[0].members.len(), 5);
    assert!(paths[..5].iter().all(|path| sets[0].members.contains(path)));
}

#[test]
fn native_names_and_serialized_object_types() {
    let game = identified();
    assert_eq!(
        game.resource_route("cg.cr6ti", ResourceOrigin::File, &[]),
        ResourceRoute::Image("image/rugp")
    );
    assert_eq!(
        game.resource_route("voice.oor", ResourceOrigin::File, &[]),
        ResourceRoute::Audio("oor/rugp")
    );
    assert_eq!(
        game.resource_route("root.rio", ResourceOrigin::Entry(ResourceKind::Data), &[]),
        ResourceRoute::Script("object/rugp")
    );
    assert!(matches!(
        game.resource_route("root.rio", ResourceOrigin::File, &[]),
        ResourceRoute::Archive(_)
    ));
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
