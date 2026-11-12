#![allow(clippy::unwrap_used)]

use super::*;
use crate::{Identification, identify};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use vnlens_core::{Error, ResourceOrigin, ResourceRoute};
use vnlens_io::BinaryWriter;

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn temp() -> Temp {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "vnlens-engine-will-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    Temp(path)
}
fn pe_bytes(text: &[u8]) -> Vec<u8> {
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
fn archive_tag(game: &Identification, name: &str) -> &'static str {
    match game.resource_route(name, ResourceOrigin::File, &[]) {
        ResourceRoute::Archive(route) => route.tag,
        _ => "missing archive route",
    }
}

#[test]
fn pe_strings_precede_layout_and_archive_bytes_are_not_evidence() {
    let dir = temp();
    let cancel = AtomicBool::new(false);
    fs::write(dir.0.join("renamed.exe"), pe_bytes(b"AdvHD\0WillPlus\0")).unwrap();
    fs::create_dir(dir.0.join("pac")).unwrap();
    fs::write(dir.0.join("pac/Scripts.ypf"), b"broken").unwrap();
    fs::write(dir.0.join("pac/Graphics.ypf"), b"broken").unwrap();
    let game = identify(&dir.0, &cancel).unwrap().unwrap();
    assert_eq!(game.engine, Engine::Will);
    assert!(game.evidence.starts_with("PE features"));
    assert_eq!(archive_tag(&game, "random.arc"), "arc/willv2");
    assert!(!matches!(
        game.resource_route("Scripts.ypf", ResourceOrigin::File, &[]),
        ResourceRoute::Archive(_)
    ));
    let movie = dir.0.join("op.dat");
    fs::write(
        &movie,
        b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c",
    )
    .unwrap();
    assert_eq!(
        game.route_path(&movie).unwrap().kind(),
        vnlens_core::ResourceKind::Video
    );
    let data = dir.0.join("save.dat");
    fs::write(&data, b"not-asf-header-0").unwrap();
    assert_eq!(
        game.route_path(&data).unwrap().kind(),
        vnlens_core::ResourceKind::Unknown
    );
    fs::remove_file(dir.0.join("renamed.exe")).unwrap();
    assert!(matches!(
        identify(&dir.0, &cancel),
        Err(Error::UnknownScheme(_))
    ));
    fs::remove_dir_all(dir.0.join("pac")).unwrap();
    fs::write(dir.0.join("standalone.arc"), b"AdvHD\0WillPlus\0").unwrap();
    assert!(identify(&dir.0, &cancel).unwrap().is_none());
    cancel.store(true, Ordering::Relaxed);
    assert!(matches!(identify(&dir.0, &cancel), Err(Error::Cancelled)));
}

#[test]
fn unicode_strings_conflicting_engines_and_missing_keys() {
    let dir = temp();
    let cancel = AtomicBool::new(false);
    let mut text = Vec::new();
    for unit in "AdvHD\0WillPlus\0".encode_utf16() {
        let mut bytes = [0; 2];
        BinaryWriter::u16_le(unit, &mut bytes);
        text.extend(bytes);
    }
    fs::write(dir.0.join("wide.exe"), pe_bytes(&text)).unwrap();
    assert_eq!(
        identify(&dir.0, &cancel).unwrap().unwrap().engine,
        Engine::Will
    );
    fs::write(
        dir.0.join("other.exe"),
        pe_bytes(b"ysbin\\yst%05d.ybn\0ysbin\\yst_list.ybn\0"),
    )
    .unwrap();
    assert!(matches!(
        identify(&dir.0, &cancel),
        Err(Error::Unsupported(_))
    ));
    fs::remove_file(dir.0.join("wide.exe")).unwrap();
    assert!(matches!(
        identify(&dir.0, &cancel),
        Err(Error::UnknownScheme(_))
    ));
}

#[test]
fn layout_fallback_and_renamed_non_pe_are_not_confused() {
    let dir = temp();
    let cancel = AtomicBool::new(false);
    fs::write(dir.0.join("fake.exe"), b"AdvHD\0WillPlus\0").unwrap();
    assert!(identify(&dir.0, &cancel).unwrap().is_none());
    for name in ["AdvHD.exe", "Script2.arc", "Graphic.arc"] {
        fs::write(dir.0.join(name), []).unwrap();
    }
    let game = identify(&dir.0, &cancel).unwrap().unwrap();
    assert_eq!(game.engine, Engine::Will);
    assert_eq!(game.evidence, "Game directory layout");
}
