#![allow(clippy::unwrap_used)]
use super::*;
use crate::{Identification, identify};
use std::{fs, path::PathBuf, sync::atomic::AtomicBool};
use vnlens_core::{ArchiveOptions, Error, ResourceKind, ResourceOrigin, ResourceRoute};
use vnlens_io::BinaryWriter;

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn temp() -> Temp {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "vnlens-artemis-engine-{}-{stamp}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    Temp(path)
}
fn image(text: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 0x200 + text.len()];
    bytes[..2].copy_from_slice(b"MZ");
    BinaryWriter::u32_le(0x80, &mut bytes[0x3c..]);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    BinaryWriter::u16_le(0x14c, &mut bytes[0x84..]);
    BinaryWriter::u16_le(1, &mut bytes[0x86..]);
    BinaryWriter::u16_le(0xe0, &mut bytes[0x94..]);
    BinaryWriter::u16_le(0x10b, &mut bytes[0x98..]);
    BinaryWriter::u32_le(0x400000, &mut bytes[0xb4..]);
    BinaryWriter::u32_le(0x200, &mut bytes[0xd4..]);
    BinaryWriter::u32_le(0x1000, &mut bytes[0x184..]);
    BinaryWriter::u32_le(text.len() as u32, &mut bytes[0x188..]);
    BinaryWriter::u32_le(0x200, &mut bytes[0x18c..]);
    bytes[0x200..].copy_from_slice(text);
    bytes
}
fn game() -> Identification {
    Identification {
        root: Default::default(),
        files: Default::default(),
        engine: Engine::Artemis,
        evidence: "Fixture".into(),
        options: ArchiveOptions::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    }
}

#[test]
fn requires_pe_evidence_before_accessing_pfs() {
    let dir = temp();
    let cancel = AtomicBool::new(false);
    fs::write(
        dir.0.join("root.pfs"),
        b"Artemis Engine Rev.3257\0\\root.pfs\0",
    )
    .unwrap();
    assert!(identify(&dir.0, &cancel).unwrap().is_none());
    fs::write(
        dir.0.join("renamed.exe"),
        image(b"Artemis Engine Rev.3257\0"),
    )
    .unwrap();
    assert!(identify(&dir.0, &cancel).unwrap().is_none());
    fs::write(
        dir.0.join("renamed.exe"),
        image(b"Artemis Engine Rev.3257\0\\root.pfs\0"),
    )
    .unwrap();
    assert_eq!(
        identify(&dir.0, &cancel).unwrap().unwrap().engine,
        Engine::Artemis
    );
    fs::write(
        dir.0.join("other.exe"),
        image(b"EntisGLS_GameWindow\0ERISAArchive\0"),
    )
    .unwrap();
    assert!(matches!(
        identify(&dir.0, &cancel),
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        identify(&dir.0, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
}

#[test]
fn metadata_routes_headers_and_native_companion_sets() -> Result<()> {
    let game = game();
    for name in ["root.PFS", "root.pfs.000", "root.pfs.999"] {
        for origin in [
            ResourceOrigin::File,
            ResourceOrigin::Entry(ResourceKind::Unknown),
        ] {
            let ResourceRoute::Archive(route) = game.resource_route(name, origin, b"XP3") else {
                return Err(Error::InvalidFormat);
            };
            assert_eq!(route.tag, "pfs/artemis");
            assert_eq!(
                route.options.numbers.get("artemis_companions"),
                (origin == ResourceOrigin::File).then_some(&1)
            );
        }
    }
    for (name, tag) in [
        ("scene.ast", "lua"),
        ("atlas.ipt", "lua"),
        ("config.tbl", "lua"),
        ("scene.iet", "text/artemis"),
        ("system.ini", "text/artemis"),
        ("bgm.ogg.sli", "text/artemis"),
        ("macro.asb", "asb/artemis"),
    ] {
        assert_eq!(
            game.resource_route(name, ResourceOrigin::File, &[]),
            ResourceRoute::Script(tag)
        );
    }
    assert_eq!(
        game.resource_route("macro.iet", ResourceOrigin::File, b"ASB\0\0"),
        ResourceRoute::Script("asb/artemis")
    );
    assert_eq!(
        game.resource_route("macro", ResourceOrigin::File, b"ASB\0\0"),
        ResourceRoute::Script("asb/artemis")
    );
    assert!(
        matches!(game.resource_route("unnamed", ResourceOrigin::File, b"pf8"), ResourceRoute::Archive(route) if route.tag == "pfs/artemis")
    );
    for name in [
        "root.pfs.1000",
        "root.pfs.00",
        "root.pfs.abc",
        "other.xp3",
        "other.ybn",
        "other.mja",
    ] {
        assert_eq!(
            game.resource_route(name, ResourceOrigin::File, b"pf8"),
            ResourceRoute::Other(ResourceKind::Unknown)
        );
    }
    assert_eq!(
        game.resource_route("cg.png", ResourceOrigin::File, b"pf8"),
        ResourceRoute::Image("image/standard")
    );
    let files: Vec<_> = [
        "Game.PFS",
        "Game.PFS.000",
        "Game.PFS.002",
        "Game.PFSx.000",
        "Game.PFS.1000",
        "Other.pfs.001",
    ]
    .map(|s| PathBuf::from("fixture").join(s))
    .into();
    let sets = game.archive_sets(&files);
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].primary, files[0]);
    assert_eq!(sets[0].members, files[..3]);
    let mut foreign = game;
    foreign.engine = Engine::Bgi;
    assert_eq!(
        foreign.resource_route("unnamed", ResourceOrigin::File, b"pf8"),
        ResourceRoute::Other(ResourceKind::Unknown)
    );
    Ok(())
}
