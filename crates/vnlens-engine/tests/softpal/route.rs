use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin};

fn identified() -> Identification {
    Identification {
        files: Default::default(),
        root: Default::default(),
        engine: Engine::Softpal,
        evidence: "Fixture".into(),
        options: ArchiveOptions::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    }
}

#[test]
fn softpal_routes_native_resources_and_rejects_foreign_structured_types() {
    let game = identified();
    assert_eq!(
        game.resource_route("FACE.PGD", ResourceOrigin::File, &[]),
        ResourceRoute::Image("pgd/softpal")
    );
    for ext in [
        "f0", "l0", "m0", "e0", "r0", "s0", "B0", "C0", "c0", "x0", "q0", "t0", "v0", "i0",
    ] {
        assert_eq!(
            game.resource_route(&format!("00000001.{ext}"), ResourceOrigin::File, &[]),
            ResourceRoute::Other(ResourceKind::Unknown)
        );
    }
}
