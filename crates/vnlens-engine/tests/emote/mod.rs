#![allow(clippy::unwrap_used)]

use super::*;
use crate::{Engine, Identification, identify};
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
        "vnlens-engine-emote-{}-{}-{}",
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
fn emote_attaches_to_host_and_never_identifies_an_engine() {
    let dir = temp();
    let cancel = AtomicBool::new(false);
    fs::create_dir(dir.0.join("plugin")).unwrap();
    let plugin = pe_bytes(b"PSBFile\0psbfile.dll\0");
    assert!(pe(&PeImage::parse(&plugin).unwrap().unwrap()).unwrap());
    fs::write(dir.0.join("plugin/psbfile.dll"), plugin).unwrap();
    assert!(identify(&dir.0, &cancel).unwrap().is_none());
    fs::write(dir.0.join("host.exe"), pe_bytes(b"AdvHD\0WillPlus\0")).unwrap();
    let game = identify(&dir.0, &cancel).unwrap().unwrap();
    assert_eq!(game.engine, Engine::Will);
    assert!(game.supports_psb());
    assert_eq!(archive_tag(&game, "data.arc"), "arc/willv2");
    assert_eq!(archive_tag(&game, "body.psb"), "psb");
    assert_eq!(archive_tag(&game, "pack_info.psb.m"), "psb/archive-info");
    fs::write(
        dir.0.join("hxv4.dll"),
        pe_bytes(b"Hxv4\0PARAMS\0FilterManager\0"),
    )
    .unwrap();
    assert!(matches!(
        identify(&dir.0, &cancel),
        Err(Error::Unsupported(_))
    ));
    fs::remove_file(dir.0.join("host.exe")).unwrap();
    assert!(matches!(
        identify(&dir.0, &cancel),
        Err(Error::UnknownScheme(_))
    ));
}
