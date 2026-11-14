use super::*;
use crate::{Engine, Identification};
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin};

fn identified() -> Identification {
    Identification {
        files: Default::default(),
        root: Default::default(),
        engine: Engine::Bgi,
        evidence: "Fixture".into(),
        options: ArchiveOptions::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    }
}

#[test]
fn native_names_and_ordinary_media_routes() {
    use ResourceRoute::{Audio, Image, Other, Script};
    let game = identified();
    for (name, expected) in [
        ("cg._bg", Image("image/bgi")),
        ("voice.BW", Audio("bw/bgi")),
        ("scene._bp", Script("script/bgi")),
        ("cg.png", Image("image/standard")),
        ("folder.msc/unknown", Other(ResourceKind::Unknown)),
    ] {
        assert_eq!(
            game.resource_route(name, ResourceOrigin::File, &[]),
            expected
        );
    }
    assert!(matches!(
        game.resource_route("voice.ogg", ResourceOrigin::File, &[]),
        ResourceRoute::Media { .. }
    ));
}

#[test]
fn accessed_headers_resolve_extensionless_and_transformed_entries() {
    let game = identified();
    let entry = ResourceOrigin::Entry(ResourceKind::Unknown);
    assert_eq!(
        game.resource_route("000001", entry, b"CompressedBG___\0"),
        ResourceRoute::Image("image/bgi")
    );
    assert_eq!(
        game.resource_route("000002", entry, b"BurikoCompiledScriptVer1.00\0"),
        ResourceRoute::Script("script/bgi")
    );
    assert_eq!(
        game.resource_route("voice.bw", entry, b"OggS"),
        ResourceRoute::Audio("bw/bgi")
    );
    assert_ne!(
        game.resource_route("0000", ResourceOrigin::File, b"BMP "),
        ResourceRoute::Image("dwq/systemnnn")
    );
    assert_eq!(
        game.resource_route("0000", ResourceOrigin::File, &[2, 0, 16, 0]),
        ResourceRoute::Other(ResourceKind::Unknown)
    );
    assert_eq!(
        game.resource_route("entry", entry, &[0xfa, 0xfa, b'R', b'I']),
        ResourceRoute::Other(ResourceKind::Unknown)
    );
    assert_eq!(
        game.resource_route("movie/op.webm", ResourceOrigin::File, &[]),
        ResourceRoute::Video("ffmpeg")
    );
    assert!(matches!(
        game.resource_route("texture.psz", ResourceOrigin::File, b"PSZ\0"),
        ResourceRoute::Other(_)
    ));
}
