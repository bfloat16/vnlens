use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin};

fn identified() -> Identification {
    Identification {
        files: Default::default(),
        root: Default::default(),
        engine: Engine::Yuris,
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
        game.resource_route("cg.YCG", ResourceOrigin::File, &[]),
        ResourceRoute::Image("ycg/yuris")
    );
    assert_eq!(
        game.resource_route("scene.YBN", ResourceOrigin::File, &[]),
        ResourceRoute::Script("ybn/yuris")
    );
    assert_eq!(
        game.resource_route("movie.YMV", ResourceOrigin::File, &[]),
        ResourceRoute::Video("ymv/yuris")
    );
    assert_eq!(
        game.resource_route(
            "movie.ymv",
            ResourceOrigin::Entry(ResourceKind::Image),
            b"YSMV"
        ),
        ResourceRoute::Video("ymv/yuris")
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
