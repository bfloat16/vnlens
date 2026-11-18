use super::*;
use crate::Engine;
use std::{
    borrow::Cow,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

fn game(engine: Engine) -> Identification {
    Identification {
        root: PathBuf::from("fixture"),
        engine,
        evidence: "Fixture".into(),
        files: Default::default(),
        options: Default::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    }
}

#[test]
fn registered_suffixes_win_over_native_and_standard_headers() {
    for (engine, name, expected) in [
        (
            Engine::Yuris,
            "image.ycg",
            ResourceRoute::Image("ycg/yuris"),
        ),
        (
            Engine::Kaleido,
            "movie.webm",
            ResourceRoute::Video("webm/kaleido"),
        ),
        (Engine::Bgi, "voice.bw", ResourceRoute::Audio("bw/bgi")),
        (
            Engine::Will,
            "scene.json",
            ResourceRoute::Script("json/will"),
        ),
    ] {
        let identified = game(engine);
        for origin in [
            ResourceOrigin::File,
            ResourceOrigin::Entry(ResourceKind::Unknown),
        ] {
            for header in [&b"OggS"[..], &b"YSMV"[..], &b"PSB\0"[..], &b"BM"[..]] {
                assert_eq!(identified.resource_route(name, origin, header), expected);
            }
        }
    }
    let game = game(Engine::Yuris);
    assert_eq!(
        game.resource_route("image.png", ResourceOrigin::File, b"YSMV"),
        ResourceRoute::Image("image/standard")
    );
    assert_eq!(
        game.resource_route("image.unknown", ResourceOrigin::File, b"YSMV"),
        ResourceRoute::Other(ResourceKind::Unknown)
    );
}

#[test]
fn extensionless_archives_and_resources_stay_in_the_selected_engine() {
    for (engine, magic, tag) in [
        (Engine::Yuris, &b"YPF\0"[..], "ypf/yuris"),
        (Engine::Krkr, &b"XP3\r\n \n\x1a\x8bg\x01"[..], "xp3/krkr"),
        (Engine::Bgi, &b"BURIKO ARC20"[..], "arc/bgi"),
        (Engine::Bgi, &b"PackFile    "[..], "arc/bgi"),
        (Engine::Softpal, &b"PAC "[..], "pac/softpal"),
        (Engine::Escude, &b"ESC-ARC2"[..], "bin/escude"),
        (Engine::Mages, &b"MPK\0"[..], "mpk/mages"),
        (Engine::Siglus, &b"\x5c\0\0\0"[..], "pck/siglus"),
        (Engine::Siglus, &b"\xa8\0\0\0"[..], "omv/siglus"),
    ] {
        let identified = game(engine);
        for origin in [
            ResourceOrigin::File,
            ResourceOrigin::Entry(ResourceKind::Unknown),
        ] {
            assert!(
                matches!(identified.resource_route("unnamed", origin, magic), ResourceRoute::Archive(route) if route.tag == tag)
            );
            assert_eq!(
                identified.resource_route("unnamed", origin, &[]),
                ResourceRoute::Other(ResourceKind::Unknown)
            );
        }
        let foreign = game(Engine::NintendoSwitch);
        assert_eq!(
            foreign.resource_route("unnamed", ResourceOrigin::File, magic),
            ResourceRoute::Other(ResourceKind::Unknown)
        );
    }
    let mut fpd = game(Engine::AgesMk2);
    fpd.options
        .keys
        .insert("resident", vnlens_core::Secret::new(b"fixture-key"));
    assert!(
        matches!(fpd.resource_route("unnamed", ResourceOrigin::File, b"FPD\0"), ResourceRoute::Archive(route) if route.tag == "fpd")
    );
    let rio = game(Engine::Rugp);
    assert!(
        matches!(rio.resource_route("unnamed", ResourceOrigin::File, b"\xcd\x32\x6e\x59"), ResourceRoute::Archive(route) if route.tag == "rio/rugp")
    );
    assert_eq!(
        rio.resource_route(
            "unnamed",
            ResourceOrigin::Entry(ResourceKind::Data),
            b"\xcd\x32\x6e\x59"
        ),
        ResourceRoute::Script("object/rugp")
    );
    assert_eq!(
        game(Engine::Yuris).resource_route(
            "unnamed",
            ResourceOrigin::Entry(ResourceKind::Unknown),
            b"YSMV"
        ),
        ResourceRoute::Video("ymv/yuris")
    );
    assert_eq!(
        game(Engine::Yuris).resource_route("unnamed", ResourceOrigin::File, b"BM"),
        ResourceRoute::Image("image/standard")
    );
}

struct Counted(Arc<AtomicUsize>);
impl vnlens_io::ReadAt for Counted {
    fn len(&self) -> u64 {
        4
    }
    fn read_at(&self, offset: u64, size: usize) -> std::io::Result<Cow<'_, [u8]>> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(Cow::Borrowed(vnlens_io::BinaryReader::bytes_at(
            b"YSMV",
            usize::try_from(offset).map_err(std::io::Error::other)?,
            size,
        )?))
    }
}

#[test]
fn disk_routing_reads_only_extensionless_prefixes() -> Result<()> {
    let mut game = game(Engine::Yuris);
    let reads = Arc::new(AtomicUsize::new(0));
    let mut files = vnlens_io::FileSystem::isolated(game.root.clone());
    for name in ["native.ycg", "standard.png", "unknown.bin", "unnamed"] {
        files.insert(game.root.join(name), Arc::new(Counted(reads.clone())))?;
    }
    game.files = Arc::new(files);
    for name in ["native.ycg", "standard.png", "unknown.bin"] {
        let _ = game.route_path(&game.root.join(name))?;
    }
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    assert_eq!(
        game.route_path(&game.root.join("unnamed"))?,
        ResourceRoute::Video("ymv/yuris")
    );
    assert_eq!(reads.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn header_priority_reads_only_the_selected_prefix_and_keeps_io_errors() -> Result<()> {
    let mut game = game(Engine::Yuris);
    let reads = Arc::new(AtomicUsize::new(0));
    let mut files = vnlens_io::FileSystem::isolated(game.root.clone());
    let path = game.root.join("movie.YPF");
    files.insert(path.clone(), Arc::new(Counted(reads.clone())))?;
    game.files = Arc::new(files);
    assert!(matches!(
        game.resource_route("movie.YPF", ResourceOrigin::File, &[]),
        ResourceRoute::Archive(_)
    ));
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    assert_eq!(game.route_path(&path)?, ResourceRoute::Video("ymv/yuris"));
    assert_eq!(reads.load(Ordering::Relaxed), 1);
    // The exemption is per format; the engine's other suffixes stay authoritative.
    assert_eq!(
        game.route_path(&game.root.join("missing.ycg"))?,
        ResourceRoute::Image("ycg/yuris")
    );
    assert!(matches!(
        game.route_path(&game.root.join("missing.ypf")),
        Err(vnlens_core::Error::Io(_))
    ));
    Ok(())
}
