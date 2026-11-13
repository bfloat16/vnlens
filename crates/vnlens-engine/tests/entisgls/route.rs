use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ResourceKind, ResourceOrigin};

#[test]
fn routes_archive_without_payload_and_rejects_foreign_formats() {
    let game = Identification {
        root: Default::default(),
        engine: Engine::EntisGls,
        evidence: "Fixture".into(),
        files: Default::default(),
        options: Default::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    };
    assert!(
        matches!(game.resource_route("DATA.NOA", ResourceOrigin::File, &[]), ResourceRoute::Archive(route) if route.tag == "noa/entisgls")
    );
    for name in ["foreign.xp3", "foreign.g00", "foreign.ws2"] {
        assert_eq!(
            game.resource_route(name, ResourceOrigin::File, &[]),
            ResourceRoute::Other(ResourceKind::Unknown)
        );
    }
    for (name, expected) in [
        ("ui.ERI", ResourceRoute::Image("eri/entisgls")),
        ("voice.MIO", ResourceRoute::Audio("mio/entisgls")),
        ("opening.MEI", ResourceRoute::Video("mei/entisgls")),
        ("script.CSX", ResourceRoute::Script("csx/entisgls")),
    ] {
        assert_eq!(
            game.resource_route(name, ResourceOrigin::File, &[]),
            expected
        );
    }
    let mut header = b"Entis\x1a\0\0\0\0\0\0\0\0\0\0Music Interleaved".to_vec();
    vnlens_io::BinaryWriter::u32_le(0x03000100, &mut header[8..]);
    assert_eq!(
        game.resource_route("renamed.eri", ResourceOrigin::File, &header),
        ResourceRoute::Audio("mio/entisgls")
    );
}
