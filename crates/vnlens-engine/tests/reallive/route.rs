use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ResourceKind, ResourceOrigin};

#[test]
fn shared_formats_scene_container_and_no_cross_engine_routes() {
    let game = Identification {
        files: Default::default(),
        root: Default::default(),
        engine: Engine::RealLive,
        evidence: "Fixture".into(),
        options: Default::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    };
    for (name, expected) in [
        ("cg.G00", ResourceRoute::Image("g00/siglus")),
        ("cg.PDT", ResourceRoute::Image("pdt/reallive")),
        ("voice.NWA", ResourceRoute::Audio("nwa/siglus")),
        ("anime.GAN", ResourceRoute::Script("script/siglus")),
        ("Seen0042.txt", ResourceRoute::Script("script/reallive")),
        ("Gameexe.ini", ResourceRoute::Script("script/reallive")),
    ] {
        assert_eq!(
            game.resource_route(name, ResourceOrigin::File, &[]),
            expected
        );
    }
    for (name, tag) in [
        ("SEEN.TXT", "seen/reallive"),
        ("voice.ovk", "voice/siglus"),
        ("voice.nwk", "voice/siglus"),
    ] {
        assert!(
            matches!(game.resource_route(name, ResourceOrigin::File, &[]), ResourceRoute::Archive(route) if route.tag == tag)
        );
    }
    assert_eq!(
        game.resource_route("cg.g00", ResourceOrigin::File, &[0, 0, 1, 0, 1]),
        ResourceRoute::Image("g00/siglus")
    );
    assert_eq!(
        game.resource_route(
            "unknown",
            ResourceOrigin::Entry(ResourceKind::Script),
            &[0xd0, 1, 0, 0]
        ),
        ResourceRoute::Script("script/reallive")
    );
    for name in ["Scene.pck", "Scene.ss", "data.xp3", "cg.tlg", "script.ybn"] {
        assert_eq!(
            game.resource_route(name, ResourceOrigin::File, &[]),
            ResourceRoute::Other(ResourceKind::Unknown)
        );
    }
    assert!(matches!(
        game.resource_route("voice.ogg", ResourceOrigin::File, &[]),
        ResourceRoute::Media { .. }
    ));
    assert_eq!(
        game.resource_route("movie.mp4", ResourceOrigin::File, &[]),
        ResourceRoute::Video("ffmpeg")
    );
}
