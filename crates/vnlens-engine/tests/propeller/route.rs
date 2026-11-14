use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin};

fn identified() -> Identification {
    Identification {
        files: Default::default(),
        root: Default::default(),
        engine: Engine::Propeller,
        evidence: "Fixture".into(),
        options: ArchiveOptions::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    }
}

#[test]
fn native_names_and_headerless_priority_over_standard_magic() {
    let game = identified();
    assert_eq!(
        game.resource_route("cg.MGR", ResourceOrigin::File, &[]),
        ResourceRoute::Image("image/propeller-mgr")
    );
    assert_eq!(
        game.resource_route("scenario.MSC", ResourceOrigin::File, &[]),
        ResourceRoute::Script("msc/propeller")
    );
    assert_eq!(
        game.resource_route("scene.msc", ResourceOrigin::File, b"OggS"),
        ResourceRoute::Script("msc/propeller")
    );
    assert!(matches!(
        game.resource_route("movie.mpk", ResourceOrigin::File, &[]),
        ResourceRoute::Archive(_)
    ));
    assert!(matches!(
        game.resource_route("movie.mpk", ResourceOrigin::File, b"\0\0\x01\xba"),
        ResourceRoute::Archive(route) if route.tag == "mpk/propeller"
    ));
    assert_eq!(
        game.resource_route("movie", ResourceOrigin::File, b"\0\0\x01\xba"),
        ResourceRoute::Video("ffmpeg")
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
