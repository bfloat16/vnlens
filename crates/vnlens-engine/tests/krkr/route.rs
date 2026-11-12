use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin};

fn identified() -> Identification {
    Identification {
        files: Default::default(),
        root: Default::default(),
        engine: Engine::Krkr,
        evidence: "Fixture".into(),
        options: ArchiveOptions::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    }
}

#[test]
fn pimg_composition_is_explicit_and_shared_without_changing_other_psb_routes() {
    let game = identified();
    let clone = game.clone();
    let origin = vnlens_core::ResourceOrigin::File;
    assert!(matches!(
        game.resource_route("map.pimg", origin, b"PSB\0"),
        ResourceRoute::Archive(_)
    ));
    game.set_compose_pimg(true);
    for header in [&[][..], &b"PSB\0"[..], &b"mdf\0"[..]] {
        assert_eq!(
            clone.resource_route("map.PIMG", origin, header),
            ResourceRoute::Image("pimg/krkr")
        );
    }
    assert!(matches!(
        game.resource_route("scene.psb", origin, b"PSB\0"),
        ResourceRoute::Archive(_)
    ));
    clone.set_compose_pimg(false);
    assert!(matches!(
        game.resource_route("map.pimg", origin, &[]),
        ResourceRoute::Archive(_)
    ));
}

#[test]
fn native_names_psb_shells_and_ordinary_media_routes() {
    let game = identified();
    assert!(game.supports_psb());
    assert_eq!(
        game.resource_route("cg.TLG", ResourceOrigin::File, &[]),
        ResourceRoute::Image("tlg/krkr")
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
    for (name, header) in [
        ("scenario.mzs", &b"mzs\0"[..]),
        ("scenario.psz", &b"PSZ\0"[..]),
        ("scenario.mdf", &b"mdf\0"[..]),
    ] {
        assert!(
            matches!(game.resource_route(name, ResourceOrigin::File, &[]), ResourceRoute::Archive(route) if route.tag == "psb")
        );
        assert!(
            matches!(game.resource_route(name, ResourceOrigin::File, header), ResourceRoute::Archive(route) if route.tag == "psb")
        );
    }
}

#[test]
fn compiled_scenarios_are_psb_containers_during_listing_and_access() {
    for engine in [Engine::Krkr, Engine::KrkrzHxv4] {
        let mut game = identified();
        game.engine = engine;
        for origin in [
            ResourceOrigin::File,
            ResourceOrigin::Entry(ResourceKind::Unknown),
            ResourceOrigin::Entry(ResourceKind::Script),
        ] {
            for name in ["ks.scn", "scenario/chapter.ks.scn", "SCENARIO\\CHAPTER.SCN"] {
                for header in [&[][..], &b"PSB\0"[..], &b"mdf\0"[..]] {
                    assert!(matches!(
                        game.resource_route(name, origin, header),
                        ResourceRoute::Archive(route) if route.tag == "psb"
                    ));
                }
            }
            assert_eq!(
                game.resource_route("chapter.ks", origin, &[]),
                ResourceRoute::Script("script/krkr")
            );
            assert_eq!(
                game.resource_route("chapter.scn", origin, b"TJS2"),
                ResourceRoute::Script("script/krkr")
            );
        }
    }
    let mut unrelated = identified();
    unrelated.engine = Engine::Will;
    assert_eq!(
        unrelated.resource_route("ks.scn", ResourceOrigin::File, &[]),
        ResourceRoute::Other(ResourceKind::Unknown)
    );
}
