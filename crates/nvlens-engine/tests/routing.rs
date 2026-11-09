use super::*;
use nvlens_core::ArchiveOptions;

fn identified(engine: Engine) -> Identification {
    Identification {
        root: Default::default(),
        engine,
        evidence: "Fixture".into(),
        options: ArchiveOptions::default(),
        emote: None,
    }
}

#[test]
fn native_names_are_scoped_to_their_engine() {
    use ResourceRoute::{Audio, Image, Script, Video};
    let cases = [
        (Engine::Propeller, "cg.MGR", Image("image/propeller-mgr")),
        (Engine::Propeller, "scenario.MSC", Script("msc/propeller")),
        (Engine::Siglus, "cg.G00", Image("g00/siglus")),
        (Engine::Siglus, "voice.NWA", Audio("nwa/siglus")),
        (Engine::Siglus, "scene.SS", Script("script/siglus")),
        (Engine::Bgi, "cg._bg", Image("image/bgi")),
        (Engine::Bgi, "voice.BW", Audio("bw/bgi")),
        (Engine::Bgi, "scene._bp", Script("script/bgi")),
        (Engine::Exhibit, "cg.LVG", Image("gyu/exhibit")),
        (Engine::Exhibit, "cg.DLT", Image("dlt/exhibit")),
        (Engine::Exhibit, "scene.RLD", Script("rld/exhibit")),
        (Engine::Yuris, "cg.YCG", Image("ycg/yuris")),
        (Engine::Yuris, "scene.YBN", Script("ybn/yuris")),
        (Engine::Yuris, "movie.YMV", Video("ymv/yuris")),
        (Engine::Will, "cg.PNA", Image("pna/will")),
        (Engine::Will, "scene.WS2", Script("ws2/will")),
        (Engine::SystemNnn, "cg.DWQ", Image("dwq/systemnnn")),
        (Engine::SystemNnn, "voice.VAW", Audio("vaw/systemnnn")),
        (Engine::SystemNnn, "scene.SPT", Script("spt/systemnnn")),
        (Engine::Escude, "scene.LSF", Script("script/escude")),
        (Engine::Rugp, "cg.cr6ti", Image("image/rugp")),
        (Engine::Rugp, "voice.oor", Audio("oor/rugp")),
        (Engine::Krkr, "cg.TLG", Image("tlg/krkr")),
        (Engine::KrkrzHxv4, "scene.KS", Script("script/krkr")),
    ];
    for (engine, name, expected) in cases {
        assert_eq!(
            identified(engine).resource_route(name, ResourceOrigin::File, &[]),
            expected
        );
        assert_eq!(
            identified(Engine::AgesMk2).resource_route(name, ResourceOrigin::File, &[]),
            ResourceRoute::Other(ResourceKind::Unknown)
        );
    }
}

#[test]
fn ordinary_media_never_receives_a_default_script_route() {
    for engine in [
        Engine::Rugp,
        Engine::Exhibit,
        Engine::Yuris,
        Engine::Bgi,
        Engine::Siglus,
        Engine::Krkr,
        Engine::KrkrzHxv4,
        Engine::Propeller,
        Engine::Will,
        Engine::SystemNnn,
        Engine::Escude,
        Engine::AgesMk2,
    ] {
        let game = identified(engine);
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
}

#[test]
fn accessed_headers_resolve_extensionless_and_transformed_entries() {
    let entry = ResourceOrigin::Entry(ResourceKind::Unknown);
    assert_eq!(
        identified(Engine::Bgi).resource_route("000001", entry, b"CompressedBG___\0"),
        ResourceRoute::Image("image/bgi")
    );
    assert_eq!(
        identified(Engine::Bgi).resource_route("000002", entry, b"BurikoCompiledScriptVer1.00\0"),
        ResourceRoute::Script("script/bgi")
    );
    assert!(matches!(
        identified(Engine::Bgi).resource_route("voice.bw", entry, b"OggS"),
        ResourceRoute::Media { .. }
    ));
    assert_eq!(
        identified(Engine::Exhibit).resource_route("00123", entry, b"RIFFxxxxAVI "),
        ResourceRoute::Video("ffmpeg")
    );
    assert_eq!(
        identified(Engine::Will).resource_route("image.mos", entry, b"\x89PNG\r\n\x1a\n"),
        ResourceRoute::Image("image/standard")
    );
    assert_eq!(
        identified(Engine::Yuris).resource_route(
            "movie.ymv",
            ResourceOrigin::Entry(ResourceKind::Image),
            b"YSMV"
        ),
        ResourceRoute::Video("ymv/yuris")
    );
    assert_eq!(
        identified(Engine::Exhibit).resource_route("00123", entry, b"YSMV"),
        ResourceRoute::Other(ResourceKind::Unknown)
    );
}

#[test]
fn container_and_script_name_collisions_use_storage_context() {
    let game = identified(Engine::Escude);
    assert!(matches!(
        game.resource_route("data.bin", ResourceOrigin::File, &[]),
        ResourceRoute::Archive(_)
    ));
    assert_eq!(
        game.resource_route(
            "scene.bin",
            ResourceOrigin::Entry(ResourceKind::Unknown),
            b"unrecognized script bytes"
        ),
        ResourceRoute::Script("script/escude")
    );
    assert!(matches!(
        game.resource_route(
            "nested.bin",
            ResourceOrigin::Entry(ResourceKind::Unknown),
            b"ESC-ARC2"
        ),
        ResourceRoute::Archive(_)
    ));
    let game = identified(Engine::Propeller);
    assert!(matches!(
        game.resource_route("movie.mpk", ResourceOrigin::File, &[]),
        ResourceRoute::Archive(_)
    ));
    assert_eq!(
        game.resource_route("movie.mpk", ResourceOrigin::File, b"\0\0\x01\xba"),
        ResourceRoute::Video("ffmpeg")
    );
}

#[test]
fn serialized_object_types_override_container_names() {
    let game = identified(Engine::Rugp);
    assert_eq!(
        game.resource_route("root.rio", ResourceOrigin::Entry(ResourceKind::Data), &[]),
        ResourceRoute::Script("object/rugp")
    );
    assert!(matches!(
        game.resource_route("root.rio", ResourceOrigin::File, &[]),
        ResourceRoute::Archive(_)
    ));
    assert_eq!(
        identified(Engine::Will).resource_route("arc", ResourceOrigin::File, &[]),
        ResourceRoute::Other(ResourceKind::Unknown)
    );
}

#[test]
fn dwq_precedes_bmp_only_in_its_engine() {
    assert_eq!(
        identified(Engine::SystemNnn).resource_route("0000", ResourceOrigin::File, b"BMP "),
        ResourceRoute::Image("dwq/systemnnn")
    );
    assert_ne!(
        identified(Engine::Bgi).resource_route("0000", ResourceOrigin::File, b"BMP "),
        ResourceRoute::Image("dwq/systemnnn")
    );
    // A NWA-like prefix has no meaning in another engine without its name.
    assert_eq!(
        identified(Engine::Bgi).resource_route("0000", ResourceOrigin::File, &[2, 0, 16, 0]),
        ResourceRoute::Other(ResourceKind::Unknown)
    );
}

#[test]
fn headerless_native_names_precede_accidental_standard_magic() {
    // A valid type-0 G00 with width 256 and height 256 begins like an ICO.
    assert_eq!(
        identified(Engine::Siglus).resource_route("cg.g00", ResourceOrigin::File, &[0, 0, 1, 0, 1]),
        ResourceRoute::Image("g00/siglus")
    );
    assert_eq!(
        identified(Engine::Propeller).resource_route("scene.msc", ResourceOrigin::File, b"OggS"),
        ResourceRoute::Script("msc/propeller")
    );
    assert_eq!(
        identified(Engine::Escude).resource_route("scene.bin", ResourceOrigin::File, b"acp\0"),
        ResourceRoute::Script("script/escude")
    );
}
