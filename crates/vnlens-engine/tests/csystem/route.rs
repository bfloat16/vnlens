use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin, ResourceRoute};

fn identified() -> Identification {
    Identification {
        files: Default::default(),
        root: PathBuf::from("game"),
        engine: Engine::Csystem,
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
fn resource_names_follow_native_volume_templates() {
    for name in [
        "arc00.dat",
        "arc08a.dat",
        "data00.dat",
        "data000.dat",
        "resources/data071.dat",
    ] {
        assert!(archive_name(name));
    }
    for name in [
        "data01.dat",
        "data0.dat",
        "data0000.dat",
        "arc001.dat",
        "data.pac",
    ] {
        assert!(!archive_name(name));
    }
}

#[test]
fn csystem_structured_types_keep_archive_case_and_headerless_priority() {
    let game = identified();
    for (ext, tag) in [
        ("f0", "f0/csystem"),
        ("l0", "l0/csystem"),
        ("m0", "m0/csystem"),
        ("e0", "e0/csystem"),
        ("r0", "r0/csystem"),
        ("s0", "s0/csystem"),
        ("B0", "properties/csystem"),
        ("C0", "references/csystem"),
        ("c0", "animation/csystem"),
        ("x0", "x0/csystem"),
        ("q0", "q0/csystem"),
        ("t0", "t0/csystem"),
        ("v0", "v0/csystem"),
        ("i0", "movie-path/csystem"),
    ] {
        let name = format!("00000001.{ext}");
        for origin in [
            ResourceOrigin::File,
            ResourceOrigin::Entry(ResourceKind::Script),
        ] {
            assert_eq!(
                game.resource_route(&name, origin, &[]),
                ResourceRoute::Script(tag)
            );
            assert_eq!(
                game.resource_route(&name, origin, b"OggS"),
                ResourceRoute::Script(tag)
            );
        }
    }
}

#[test]
fn csystem_pairs_indexes_and_payloads_without_probing() {
    let paths = files(&[
        "Arc00.dat",
        "Arc01.dat",
        "Arc04.dat",
        "Arc02.dat",
        "Arc05.dat",
        "Resources/Data00.dat",
        "Resources/Data000.dat",
        "Resources/Data071.dat",
        "Resources/Data001.dat.bak",
    ]);
    let sets = identified().archive_sets(&paths);
    assert_eq!(sets.len(), 3);
    assert!(
        sets.iter()
            .any(|set| set.primary == paths[2] && set.members == paths[1..3])
    );
    assert!(
        sets.iter()
            .any(|set| set.primary == paths[4] && set.members == paths[3..5])
    );
    assert!(
        sets.iter()
            .any(|set| set.primary == paths[5] && set.members == paths[5..8])
    );
}

#[test]
fn csystem_includes_picture_and_movie_parts() {
    let paths = files(&[
        "Arc02.dat",
        "Arc05.dat",
        "Arc05a.dat",
        "Arc05b.dat",
        "Arc07.dat",
        "Arc08.dat",
        "Arc08a.dat",
    ]);
    let sets = identified().archive_sets(&paths);
    assert_eq!(sets.len(), 2);
    assert_eq!(sets[0].members, paths[..4]);
    assert_eq!(sets[1].members, paths[4..]);
}
