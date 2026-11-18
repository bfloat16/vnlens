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

#[test]
fn ypf_header_priority_is_explicit_and_does_not_probe_other_engines() {
    let game = identified();
    let asf = b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c";
    for origin in [
        ResourceOrigin::File,
        ResourceOrigin::Entry(ResourceKind::Archive),
    ] {
        let archive = game.resource_route("pac/ed2.YPF", origin, &[]);
        assert!(matches!(&archive, ResourceRoute::Archive(route) if route.tag == "ypf/yuris"));
        assert_eq!(
            game.resource_route("pac/ed2.YPF", origin, asf),
            ResourceRoute::Video("ffmpeg")
        );
        assert_eq!(game.resource_route("pac/sn.ypf", origin, b"YPF\0"), archive);
        assert_eq!(
            game.resource_route("pac/sn.ypf", origin, b"YSMV"),
            ResourceRoute::Video("ymv/yuris")
        );
        for header in [&b"XP3\r\n \n\x1a\x8bg\x01"[..], &b"unknown"[..], &asf[..15]] {
            assert_eq!(game.resource_route("pac/sn.ypf", origin, header), archive);
        }
        for name in ["pac/ed2.bin", "pac/ed2.unknown"] {
            assert_eq!(
                game.resource_route(name, origin, asf),
                ResourceRoute::Other(match origin {
                    ResourceOrigin::File => ResourceKind::Unknown,
                    ResourceOrigin::Entry(kind) => kind,
                })
            );
        }
        assert_eq!(
            game.resource_route("image.ycg", origin, asf),
            ResourceRoute::Image("ycg/yuris")
        );
    }
    let mut foreign = identified();
    foreign.engine = Engine::Bgi;
    assert_eq!(
        foreign.resource_route("ed2.ypf", ResourceOrigin::File, asf),
        ResourceRoute::Other(ResourceKind::Unknown)
    );
}
