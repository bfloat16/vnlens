use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin};

fn identified() -> Identification {
    Identification {
        files: Default::default(),
        root: Default::default(),
        engine: Engine::Mages,
        evidence: "Fixture".into(),
        options: ArchiveOptions::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    }
}

#[test]
fn mages_routes_archives_scripts_and_excludes_mcf_containers() {
    let game = identified();
    assert!(
        matches!(game.resource_route("script.mpk", ResourceOrigin::File, &[]), ResourceRoute::Archive(route) if route.tag == "mpk/mages")
    );
    assert_eq!(
        game.resource_route("bonus.mpk", ResourceOrigin::File, b"mcfa"),
        ResourceRoute::Other(ResourceKind::Archive)
    );
    assert_eq!(
        game.resource_route("scene.scx", ResourceOrigin::File, &[]),
        ResourceRoute::Script("scx/mages")
    );
    assert_eq!(
        game.resource_route("text.msb", ResourceOrigin::File, &[]),
        ResourceRoute::Script("msb/mages")
    );
}
