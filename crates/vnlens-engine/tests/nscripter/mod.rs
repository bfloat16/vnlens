#![allow(clippy::unwrap_used)]
use super::*;
use crate::{Identification, identify};
use std::{fs, path::PathBuf, sync::atomic::AtomicBool};
use vnlens_core::{ArchiveOptions, ResourceKind, ResourceOrigin, ResourceRoute};
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
    let path =
        std::env::temp_dir().join(format!("vnlens-nscripter-{}-{stamp}", std::process::id()));
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

#[test]
fn requires_independent_pe_evidence_not_an_archive_payload() {
    let dir = temp();
    let cancelled = AtomicBool::new(false);
    fs::write(
        dir.0.join("arc.nsa"),
        b"NScripter Version 2.82\0nscript.dat\0arc%d.nsa\0",
    )
    .unwrap();
    fs::write(dir.0.join("nscript.dat"), b"arbitrary").unwrap();
    assert!(identify(&dir.0, &cancelled).unwrap().is_none());
    fs::write(dir.0.join("game.exe"), image(b"NScripter\0nscript.dat\0")).unwrap();
    assert!(identify(&dir.0, &cancelled).unwrap().is_none());
    fs::write(
        dir.0.join("game.exe"),
        image(b"NScripter Version 2.82\0nscript.dat\0arc%d.nsa\0"),
    )
    .unwrap();
    let game = identify(&dir.0, &cancelled).unwrap().unwrap();
    assert_eq!(game.engine, Engine::NScripter);
    fs::write(
        dir.0.join("other.exe"),
        image(b"EntisGLS_GameWindow\0ERISAArchive\0"),
    )
    .unwrap();
    assert!(matches!(
        identify(&dir.0, &cancelled),
        Err(vnlens_core::Error::Unsupported(_))
    ));
    assert!(matches!(
        identify(&dir.0, &AtomicBool::new(true)),
        Err(vnlens_core::Error::Cancelled)
    ));
}

#[test]
fn suffix_and_native_name_routes_do_not_guess_other_engine_formats() {
    let game = Identification {
        root: Default::default(),
        engine: Engine::NScripter,
        evidence: "Fixture".into(),
        files: Default::default(),
        options: ArchiveOptions::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    };
    let origin = ResourceOrigin::Entry(ResourceKind::Unknown);
    assert_eq!(
        game.resource_route("voice.nbz", ResourceOrigin::File, &[]),
        ResourceRoute::Audio("nbz/nscripter")
    );
    for (name, tag) in [("arc.NSA", "nsa/nscripter"), ("arc.sar", "sar/nscripter")] {
        assert!(
            matches!(game.resource_route(name,origin,b"XP3"), ResourceRoute::Archive(a) if a.tag==tag)
        );
    }
    for (name, route) in [
        (
            "path\\NSCRIPT.DAT",
            ResourceRoute::Script("nscript/nscripter"),
        ),
        ("nscript.zat", ResourceRoute::Script("zat/nscripter")),
        ("00.txt", ResourceRoute::Script("text/nscripter")),
        ("voice.nbz", ResourceRoute::Audio("audio/standard")),
        ("bgm.mp3", ResourceRoute::Audio("audio/mpeg")),
        ("bg.jpg", ResourceRoute::Image("image/standard")),
    ] {
        assert_eq!(game.resource_route(name, origin, &[]), route);
    }
    for name in [
        "unrelated.dat",
        "script.ks",
        "sound.nwa",
        "packed.xp3",
        "unknown.foo",
    ] {
        assert_eq!(
            game.resource_route(name, origin, b"OggS"),
            ResourceRoute::Other(ResourceKind::Unknown)
        );
    }
    assert_eq!(
        game.resource_route("no_extension", origin, b"OggS"),
        ResourceRoute::Media {
            audio: "audio/standard",
            video: "ffmpeg"
        }
    );
    assert_eq!(
        game.resource_route("no_extension", origin, &[]),
        ResourceRoute::Other(ResourceKind::Unknown)
    );
}
