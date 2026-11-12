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
        "vnlens-engine-krkr-{}-{}-{}",
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
fn krkr_requires_host_evidence_and_hxv4_resolution_never_falls_back() {
    let dir = temp();
    let cancel = AtomicBool::new(false);
    fs::write(dir.0.join("data.xp3"), b"XP3").unwrap();
    assert!(identify(&dir.0, &cancel).unwrap().is_none());
    fs::write(
        dir.0.join("renamed.exe"),
        pe_bytes(b"TVP(KIRIKIRI)\0tTVPXP3Archive\0"),
    )
    .unwrap();
    let game = identify(&dir.0, &cancel).unwrap().unwrap();
    assert_eq!(game.engine, Engine::Krkr);
    assert_eq!(archive_tag(&game, "DATA.XP3"), "xp3/krkr");
    assert!(game.resource_options().numbers.is_empty());
    assert_eq!(
        game.resource_route("scene.ks", ResourceOrigin::File, &[]),
        ResourceRoute::Script("script/krkr")
    );
    assert!(!matches!(
        game.resource_route("other.arc", ResourceOrigin::File, &[]),
        ResourceRoute::Archive(_)
    ));
    fs::write(
        dir.0.join("extra.tpm"),
        pe_bytes(b"Hxv4\0PARAMS\0FilterManager\0"),
    )
    .unwrap();
    assert!(matches!(
        identify(&dir.0, &cancel),
        Err(Error::UnknownScheme(_))
    ));
    fs::remove_file(dir.0.join("extra.tpm")).unwrap();
    fs::write(dir.0.join("other.exe"), pe_bytes(b"AdvHD\0WillPlus\0")).unwrap();
    assert!(matches!(
        identify(&dir.0, &cancel),
        Err(Error::Unsupported(_))
    ));
}
