use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin};

fn identified() -> Identification {
    Identification {
        files: Default::default(),
        root: Default::default(),
        engine: Engine::Siglus,
        evidence: "Fixture".into(),
        options: ArchiveOptions::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    }
}

#[test]
fn native_names_and_headerless_priority_over_accidental_standard_magic() {
    let game = identified();
    assert_eq!(
        game.resource_route("cg.G00", ResourceOrigin::File, &[]),
        ResourceRoute::Image("g00/siglus")
    );
    assert_eq!(
        game.resource_route("voice.NWA", ResourceOrigin::File, &[]),
        ResourceRoute::Audio("nwa/siglus")
    );
    assert_eq!(
        game.resource_route("scene.SS", ResourceOrigin::File, &[]),
        ResourceRoute::Script("script/siglus")
    );
    // A valid type-0 G00 with width 256 and height 256 begins like an ICO.
    assert_eq!(
        game.resource_route("cg.g00", ResourceOrigin::File, &[0, 0, 1, 0, 1]),
        ResourceRoute::Image("g00/siglus")
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
