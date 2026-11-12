use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin};

fn identified() -> Identification {
    Identification {
        files: Default::default(),
        root: Default::default(),
        engine: Engine::Will,
        evidence: "Fixture".into(),
        options: ArchiveOptions::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    }
}

#[test]
fn native_names_and_accessed_headers() {
    let game = identified();
    assert_eq!(
        game.resource_route("cg.PNA", ResourceOrigin::File, &[]),
        ResourceRoute::Image("pna/will")
    );
    assert_eq!(
        game.resource_route("scene.WS2", ResourceOrigin::File, &[]),
        ResourceRoute::Script("ws2/will")
    );
    assert_eq!(
        game.resource_route(
            "image.mos",
            ResourceOrigin::Entry(ResourceKind::Unknown),
            b"\x89PNG\r\n\x1a\n"
        ),
        ResourceRoute::Image("image/standard")
    );
    assert_eq!(
        game.resource_route("arc", ResourceOrigin::File, &[]),
        ResourceRoute::Other(ResourceKind::Unknown)
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
