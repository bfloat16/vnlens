use super::*;
use std::sync::Arc;

fn host() -> crate::Identification {
    crate::Identification {
        root: Default::default(),
        engine: Engine::NintendoSwitch,
        evidence: "Fixture".into(),
        files: Default::default(),
        options: Default::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    }
}

#[test]
fn mounted_directory_identifies_middleware_without_guessing_a_game_engine() -> Result<()> {
    let root = PathBuf::from("game.romfs");
    let mut files = vnlens_io::FileSystem::isolated(root.clone());
    files.insert(
        root.join("GAME.cpk"),
        Arc::new(Arc::<[u8]>::from(&b"broken unrequested CPK"[..])),
    )?;
    let game = host().for_filesystem(root, Arc::new(files), &AtomicBool::new(false))?;
    assert_eq!(game.engine, Engine::NintendoSwitch);
    assert!(game.warning().is_some());
    assert!(
        matches!(game.resource_route("GAME.cpk", ResourceOrigin::File, &[]), ResourceRoute::Archive(route) if route.tag == "cri/cpk")
    );
    assert_eq!(
        game.resource_route("scene.ws2", ResourceOrigin::File, &[]),
        ResourceRoute::Other(ResourceKind::Unknown)
    );
    assert_eq!(
        game.resource_route("image.png", ResourceOrigin::File, &[]),
        ResourceRoute::Image("image/standard")
    );
    let empty = host().for_filesystem(
        PathBuf::from("empty"),
        Arc::new(vnlens_io::FileSystem::isolated(PathBuf::from("empty"))),
        &AtomicBool::new(false),
    )?;
    assert!(matches!(
        empty.resource_route("GAME.cpk", ResourceOrigin::File, b"CPK "),
        ResourceRoute::Other(_)
    ));
    Ok(())
}

#[test]
fn mounted_directory_uses_real_engine_layout_and_keeps_cancellation() -> Result<()> {
    let root = PathBuf::from("game.romfs");
    let mut files = vnlens_io::FileSystem::isolated(root.clone());
    for name in ["AdvHD.exe", "Script2.arc", "Graphic.arc"] {
        files.insert(root.join(name), Arc::new(Arc::<[u8]>::from([])))?;
    }
    let files = Arc::new(files);
    let game = host().for_filesystem(root.clone(), files.clone(), &AtomicBool::new(false))?;
    assert_eq!(game.engine, Engine::Will);
    assert!(game.warning().is_none());
    assert_eq!(
        game.resource_route("scene.ws2", ResourceOrigin::File, &[]),
        ResourceRoute::Script("ws2/will")
    );
    assert!(matches!(
        host().for_filesystem(root, files, &AtomicBool::new(true)),
        Err(vnlens_core::Error::Cancelled)
    ));
    Ok(())
}

#[test]
fn container_identity_requires_declared_outer_format() -> Result<()> {
    let pfs = ArcView::from_bytes(
        "game.nsp".into(),
        Arc::from(&b"PFS0\0\0\0\0\0\0\0\0\0\0\0\0"[..]),
    );
    assert!(file(&pfs)?);
    let other = ArcView::from_bytes("game.arc".into(), Arc::from(&b"PFS0"[..]));
    assert!(!file(&other)?);
    let bad = ArcView::from_bytes("game.xci".into(), Arc::from(&b"HEAD"[..]));
    assert!(!file(&bad)?);
    for offset in [0x100, 0x1100] {
        let mut bytes = vec![0; offset + 4];
        bytes[offset..].copy_from_slice(b"HEAD");
        let unnamed = ArcView::from_bytes("game".into(), bytes.into());
        assert!(file(&unnamed)?);
        assert!(
            matches!(host().resource_route("game", ResourceOrigin::File, unnamed.slice(0, unnamed.len())?), ResourceRoute::Archive(route) if route.tag == "ns/xci")
        );
    }
    Ok(())
}

#[test]
fn ns_context_routes_only_its_filesystems_and_standard_resources() {
    let game = crate::Identification {
        root: Default::default(),
        engine: Engine::NintendoSwitch,
        evidence: "fixture".into(),
        files: Default::default(),
        options: Default::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    };
    for (name, origin, tag) in [
        ("game.xci", ResourceOrigin::File, "ns/xci"),
        (
            "secure",
            ResourceOrigin::Entry(ResourceKind::Archive),
            "ns/hfs0",
        ),
        (
            "content.nca",
            ResourceOrigin::Entry(ResourceKind::Unknown),
            "ns/nca",
        ),
        (
            "section1.romfs",
            ResourceOrigin::Entry(ResourceKind::Archive),
            "ns/romfs",
        ),
    ] {
        assert!(
            matches!(game.resource_route(name, origin, &[]), ResourceRoute::Archive(route) if route.tag == tag)
        );
    }
    assert!(
        matches!(game.resource_route("inner", ResourceOrigin::File, b"PFS0"), ResourceRoute::Archive(route) if route.tag == "ns/pfs0")
    );
    assert!(matches!(
        game.resource_route("inner.xp3", ResourceOrigin::File, b"XP3"),
        ResourceRoute::Other(_)
    ));
    assert!(matches!(
        game.resource_route("voice.ogg", ResourceOrigin::File, &[]),
        ResourceRoute::Media { .. }
    ));
    assert!(matches!(
        game.resource_route("secure", ResourceOrigin::File, &[]),
        ResourceRoute::Other(_)
    ));
}
