use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ResourceKind, ResourceOrigin};

#[test]
fn header_priority_only_uses_identified_middleware() {
    let mut game = Identification {
        root: Default::default(),
        engine: Engine::Yuris,
        evidence: "fixture".into(),
        files: Default::default(),
        options: Default::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    };
    assert!(
        matches!(game.resource_route("bank.ypf", ResourceOrigin::File, b"AFS2"), ResourceRoute::Archive(route) if route.tag == "ypf/yuris")
    );
    game.middleware.push(&ROUTER);
    assert!(
        matches!(game.resource_route("bank.ypf", ResourceOrigin::File, b"AFS2"), ResourceRoute::Archive(route) if route.tag == "cri/awb")
    );
}
#[test]
fn ns_and_identified_cri_middleware_route_metadata_and_logical_headers() {
    let mut game = Identification {
        root: Default::default(),
        engine: Engine::NintendoSwitch,
        evidence: "fixture".into(),
        files: Default::default(),
        options: Default::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    };
    assert!(matches!(
        game.resource_route("game.cpk", ResourceOrigin::File, &[]),
        ResourceRoute::Other(_)
    ));
    game.middleware = vec![&ROUTER];
    for name in ["game.cpk", "game.pck", "se.acb", "se.awb"] {
        assert!(matches!(
            game.resource_route(name, ResourceOrigin::File, &[]),
            ResourceRoute::Archive(_)
        ));
    }
    assert!(matches!(
        game.resource_route("op.usm", ResourceOrigin::File, &[]),
        ResourceRoute::Video("cri/usm")
    ));
    assert!(matches!(
        game.resource_route("0", ResourceOrigin::Entry(ResourceKind::Audio), b"HCA\0"),
        ResourceRoute::Audio("cri/hca")
    ));
    game.engine = Engine::Siglus;
    game.middleware = vec![&ROUTER];
    assert!(matches!(
        game.resource_route("op.usm", ResourceOrigin::File, &[]),
        ResourceRoute::Video("cri/usm")
    ));
    assert!(
        matches!(game.resource_route("scene.pck",ResourceOrigin::File,&[]),ResourceRoute::Archive(route) if route.tag=="pck/siglus")
    );
    assert!(
        matches!(game.resource_route("scene.pck",ResourceOrigin::File,b"CPK "),ResourceRoute::Archive(route) if route.tag=="pck/siglus")
    );
    game.middleware.clear();
    assert!(matches!(
        game.resource_route("movie.usm", ResourceOrigin::File, &[]),
        ResourceRoute::Other(_)
    ));
}
