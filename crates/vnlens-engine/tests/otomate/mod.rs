use super::*;
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};
use vnlens_core::{Error, ResourceKind, ResourceOrigin, ResourceRoute};
use vnlens_io::BinaryWriter;

fn executable(markers: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 0x200 + markers.len()];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    for (at, value) in [
        (0x3c, 0x80),
        (0xb4, 0x400000),
        (0xd4, 0x200),
        (0x184, 0x1000),
        (0x188, markers.len() as u32),
        (0x18c, 0x200),
    ] {
        BinaryWriter::u32_le(value, &mut bytes[at..]);
    }
    for (at, value) in [(0x84, 0x14c), (0x86, 1), (0x94, 0xe0), (0x98, 0x10b)] {
        BinaryWriter::u16_le(value, &mut bytes[at..]);
    }
    bytes[0x200..].copy_from_slice(markers);
    bytes
}

#[test]
fn executable_requires_independent_markers_and_takes_priority_over_layout() -> Result<()> {
    for markers in [
        b"STCM2SCRIPT_GROUP".as_slice(),
        b"FILE_COLLECTION",
        b"STCM2",
    ] {
        let data = executable(markers);
        let image = PeImage::parse(&data)?.ok_or(Error::InvalidFormat)?;
        assert!(!pe(&image)?);
    }
    let mut context = fixture_context(None)?;
    // RealLive layout must not override independently established PE evidence.
    Arc::make_mut(&mut context.files).insert(
        context.root.join("RealLive.exe"),
        Arc::new(Arc::<[u8]>::from(executable(
            b"STCM2SCRIPT_GROUP\0FILE_COLLECTION\0",
        ))),
    )?;
    let game = crate::detect::identify_context(context, &AtomicBool::new(false), &|_, _| {})?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(game.engine, Engine::Otomate);
    let mut context = fixture_context(None)?;
    Arc::make_mut(&mut context.files).insert(
        context.root.join("game.exe"),
        Arc::new(Arc::<[u8]>::from(executable(
            b"STCM2SCRIPT_GROUP\0FILE_COLLECTION\0EntisGLS_GameWindow\0ERISAArchive\0",
        ))),
    )?;
    assert!(matches!(
        crate::detect::identify_context(context, &AtomicBool::new(false), &|_, _| {}),
        Err(Error::Unsupported(_))
    ));
    Ok(())
}

#[test]
fn extracted_script_identity_uses_only_its_prefix() -> Result<()> {
    let mut context = fixture_context(Some("STORY"))?;
    Arc::make_mut(&mut context.files).insert(
        context.root.join("SCRIPT/100.DAT"),
        Arc::new(Arc::<[u8]>::from(&b"STCM2L"[..])),
    )?;
    let game = crate::detect::identify_context(context, &AtomicBool::new(false), &|_, _| {})?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(game.engine, Engine::Otomate);
    Ok(())
}

fn fixture_context(missing: Option<&str>) -> Result<Context> {
    let root = PathBuf::from("otomate.romfs");
    let mut files = vnlens_io::FileSystem::isolated(root.clone());
    for name in ["SYSTEM", "STORY", "GAME", "MOVIE", "SOUND"] {
        if missing == Some(name) {
            continue;
        }
        // Invalid, unrequested payloads must not affect layout recognition.
        files.insert(
            root.join(format!("CONTENTS/{name}.cpk")),
            Arc::new(Arc::<[u8]>::from(&b"unread payload"[..])),
        )?;
    }
    Ok(Context {
        root,
        files: Arc::new(files),
        sections: Default::default(),
    })
}

#[test]
fn identifies_virtual_layout_without_opening_banks() -> Result<()> {
    assert!(!layout(&fixture_context(Some("STORY"))?));
    let game = crate::detect::identify_context(
        fixture_context(None)?,
        &AtomicBool::new(false),
        &|_, _| {},
    )?
    .ok_or(Error::InvalidFormat)?;
    assert_eq!(game.engine, Engine::Otomate);
    assert!(game.warning().is_none());
    assert!(
        matches!(game.resource_route("CONTENTS/STORY.cpk", ResourceOrigin::File, &[]), ResourceRoute::Archive(route) if route.tag == "cri/cpk")
    );
    for (name, expected) in [
        ("SCRIPT/100.DAT", ResourceRoute::Script("stcm2/otomate")),
        ("image.tid", ResourceRoute::Image("tid/otomate")),
        ("voice.hca", ResourceRoute::Audio("cri/hca")),
        ("op.usm", ResourceRoute::Video("cri/usm")),
    ] {
        assert_eq!(
            game.resource_route(name, ResourceOrigin::Entry(ResourceKind::Unknown), &[]),
            expected
        );
    }
    for (head, expected) in [
        (&b"STCM2L"[..], ResourceRoute::Script("stcm2/otomate")),
        (&b"TID\x90"[..], ResourceRoute::Image("tid/otomate")),
    ] {
        assert_eq!(
            game.resource_route("untyped", ResourceOrigin::File, head),
            expected
        );
        assert_eq!(
            game.resource_route("untyped.unknown", ResourceOrigin::File, head),
            ResourceRoute::Other(ResourceKind::Unknown)
        );
    }
    assert!(
        matches!(game.resource_route("collection.CL3", ResourceOrigin::File, &[]), ResourceRoute::Archive(route) if route.tag == "cl3/otomate")
    );
    for name in ["foreign.xp3", "foreign.ws2", "foreign.g00"] {
        assert_eq!(
            game.resource_route(name, ResourceOrigin::File, b"STCM2L"),
            ResourceRoute::Other(ResourceKind::Unknown)
        );
    }
    assert!(matches!(
        crate::detect::identify_context(fixture_context(None)?, &AtomicBool::new(true), &|_, _| {}),
        Err(Error::Cancelled)
    ));
    Ok(())
}

#[test]
fn ns_mount_resolves_own_game_context() -> Result<()> {
    let context = fixture_context(None)?;
    let host = crate::Identification {
        root: PathBuf::new(),
        engine: Engine::NintendoSwitch,
        evidence: "Fixture".into(),
        options: Default::default(),
        files: Default::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    };
    let game = host.for_filesystem(context.root, context.files, &AtomicBool::new(false))?;
    assert_eq!(game.engine, Engine::Otomate);
    Ok(())
}
