use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin};

fn identified() -> Identification {
    Identification {
        files: Default::default(),
        root: Default::default(),
        engine: Engine::Escude,
        evidence: "Fixture".into(),
        options: ArchiveOptions::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    }
}

#[test]
fn native_names_and_ordinary_media_routes() {
    let game = identified();
    assert_eq!(
        game.resource_route("scene.LSF", ResourceOrigin::File, &[]),
        ResourceRoute::Script("script/escude")
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

#[test]
fn container_and_script_name_collisions_use_storage_context() {
    let game = identified();
    assert!(matches!(
        game.resource_route("data.bin", ResourceOrigin::File, &[]),
        ResourceRoute::Archive(_)
    ));
    assert_eq!(
        game.resource_route(
            "scene.bin",
            ResourceOrigin::Entry(ResourceKind::Unknown),
            b"unrecognized script bytes"
        ),
        ResourceRoute::Script("script/escude")
    );
    assert!(matches!(
        game.resource_route(
            "nested.bin",
            ResourceOrigin::Entry(ResourceKind::Unknown),
            b"ESC-ARC2"
        ),
        ResourceRoute::Archive(_)
    ));
    assert_eq!(
        game.resource_route("scene.bin", ResourceOrigin::File, b"acp\0"),
        ResourceRoute::Script("script/escude")
    );
}
