use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin, ResourceRoute};

fn identified() -> Identification {
    Identification {
        files: Default::default(),
        root: PathBuf::from("game"),
        engine: Engine::Exhibit,
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
fn exhibit_uses_hex_group_boundary_and_requires_the_index_volume() {
    let paths = files(&[
        "res2a00.grp",
        "res2a01.grp",
        "res2a0f.grp",
        "res2b00.grp",
        "res2b01.grp",
        "res2c01.grp",
    ]);
    let sets = identified().archive_sets(&paths);
    assert_eq!(sets.len(), 2);
    assert_eq!(sets[0].members, paths[..3]);
    assert_eq!(sets[1].members, paths[3..5]);
}

#[test]
fn native_names_and_accessed_headers() {
    use ResourceRoute::{Image, Other, Script, Video};
    let game = identified();
    for (name, expected) in [
        ("cg.LVG", Image("gyu/exhibit")),
        ("cg.DLT", Image("dlt/exhibit")),
        ("scene.RLD", Script("rld/exhibit")),
        ("cg.png", Image("image/standard")),
        ("folder.msc/unknown", Other(ResourceKind::Unknown)),
    ] {
        assert_eq!(
            game.resource_route(name, ResourceOrigin::File, &[]),
            expected
        );
    }
    assert!(matches!(
        game.resource_route("voice.ogg", ResourceOrigin::File, &[]),
        ResourceRoute::Media { .. }
    ));
    let entry = ResourceOrigin::Entry(ResourceKind::Unknown);
    assert_eq!(
        game.resource_route("00123", entry, b"RIFFxxxxAVI "),
        Video("ffmpeg")
    );
    assert_eq!(
        game.resource_route("00123", entry, b"YSMV"),
        Other(ResourceKind::Unknown)
    );
}
