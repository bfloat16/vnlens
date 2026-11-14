use super::*;
use crate::{Engine, Identification};
use std::path::PathBuf;
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin};

fn identified() -> Identification {
    Identification {
        files: Default::default(),
        root: PathBuf::from("game"),
        engine: Engine::Kaleido,
        evidence: "Fixture".into(),
        options: ArchiveOptions::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    }
}

#[test]
fn kaleido_routes_indices_bytecode_and_standard_psb_children() {
    let game = identified();
    assert!(game.supports_psb());
    let paths: Vec<PathBuf> = [
        "sample_info.psb.m",
        "sample_body.bin",
        "samplebody.bin",
        "sample.bin",
    ]
    .iter()
    .map(|name| PathBuf::from("game").join(name))
    .collect();
    assert_eq!(game.archive_sets(&paths).len(), 1);
    assert!(
        matches!(game.resource_route("scenario_info.psb.m", ResourceOrigin::File, b"mzs\0"), ResourceRoute::Archive(route) if route.tag == "psb/archive-info")
    );
    assert!(
        matches!(game.resource_route("entry", ResourceOrigin::Entry(ResourceKind::Unknown), b"PSB\0"), ResourceRoute::Archive(route) if route.tag == "psb")
    );
    assert_eq!(
        game.resource_route(
            "entry",
            ResourceOrigin::Entry(ResourceKind::Unknown),
            &[0xfa, 0xfa, b'R', b'I']
        ),
        ResourceRoute::Script("script/kaleido")
    );
    assert_eq!(
        game.resource_route("script", ResourceOrigin::Entry(ResourceKind::Script), &[]),
        ResourceRoute::Script("script/kaleido")
    );
    assert_eq!(
        game.resource_route(
            "pixel.dds",
            ResourceOrigin::Entry(ResourceKind::Image),
            b"DDS "
        ),
        ResourceRoute::Image("dds")
    );
    assert_eq!(
        game.resource_route(
            "voice.xwma",
            ResourceOrigin::Entry(ResourceKind::Audio),
            b"RIFF\0\0\0\0XWMA"
        ),
        ResourceRoute::Audio("xwma")
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
fn kaleido_encrypted_movies_and_plain_containers_use_distinct_routes() {
    let game = identified();
    assert_eq!(
        game.resource_route("movie/OP.WEBM", ResourceOrigin::File, &[]),
        ResourceRoute::Video("webm/kaleido")
    );
    assert_eq!(
        game.resource_route("movie/op.webm", ResourceOrigin::File, &[42; 64]),
        ResourceRoute::Video("webm/kaleido")
    );
    assert_eq!(
        game.resource_route(
            "movie/op.webm",
            ResourceOrigin::File,
            &[0x1a, 0x45, 0xdf, 0xa3]
        ),
        ResourceRoute::Video("webm/kaleido")
    );
    assert_eq!(
        game.resource_route("steinsgate_live_en.mp4", ResourceOrigin::File, &[]),
        ResourceRoute::Video("ffmpeg")
    );
}
