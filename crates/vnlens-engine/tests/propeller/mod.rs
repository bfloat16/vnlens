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
        "vnlens-engine-propeller-{}-{}-{}",
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
fn propeller_requires_pe_evidence_and_routes_only_its_formats() {
    let dir = temp();
    let cancel = AtomicBool::new(false);
    fs::write(dir.0.join("Scenario.mpk"), b"Stuff v1.0a").unwrap();
    assert!(identify(&dir.0, &cancel).unwrap().is_none());
    fs::write(
        dir.0.join("renamed.exe"),
        pe_bytes(b"Stuff v1.0a\0system_edit.msc\0Scenario\\system.msc\0Scenario.mpk\0"),
    )
    .unwrap();
    let game = identify(&dir.0, &cancel).unwrap().unwrap();
    assert_eq!(game.engine, Engine::Propeller);
    assert_eq!(archive_tag(&game, "BG.MPK"), "mpk/propeller");
    let movie = dir.0.join("ma.mpk");
    let mut header = [0; 12];
    BinaryWriter::u32_le(0xba01_0000, &mut header);
    fs::write(&movie, header).unwrap();
    assert_eq!(
        game.route_path(&movie).unwrap().kind(),
        vnlens_core::ResourceKind::Video
    );
    assert!(matches!(
        game.route_path(&movie).unwrap(),
        ResourceRoute::Video("ffmpeg")
    ));
    let package = dir.0.join("m.mpk");
    BinaryWriter::u32_le(8, &mut header);
    fs::write(&package, header).unwrap();
    assert!(matches!(
        game.route_path(&package).unwrap(),
        ResourceRoute::Archive(_)
    ));
    assert_eq!(
        game.resource_route("system.MSC", ResourceOrigin::File, &[]),
        ResourceRoute::Script("msc/propeller")
    );
    assert!(!matches!(
        game.resource_route("data.arc", ResourceOrigin::File, &[]),
        ResourceRoute::Archive(_)
    ));
    assert!(matches!(
        game.resource_route("image.mgr", ResourceOrigin::File, &[]),
        ResourceRoute::Image(_)
    ));
}

#[test]
fn propeller_versions_select_parameters_without_guessing_or_conflicts() {
    let dir = temp();
    let cancel = AtomicBool::new(false);
    let markers = b"system_edit.msc\0Scenario\\system.msc\0Scenario.mpk\0";
    let host = dir.0.join("host.exe");
    for (class, version, key) in [("Stuff v1.0a", 10, 0x88), ("Stuff v1.4", 14, 0x77)] {
        let mut text = markers.to_vec();
        text.extend(class.bytes().chain([0]));
        fs::write(&host, pe_bytes(&text)).unwrap();
        let game = identify(&dir.0, &cancel).unwrap().unwrap();
        assert_eq!(game.engine, Engine::Propeller);
        assert_eq!(
            game.options.numbers.get("propeller_msc_version"),
            Some(&version)
        );
        assert!(game.options.keys["propeller_msc"].bytes() == [key]);
        assert!(game.options.keys["propeller_mpk"].bytes() == [0x58]);
    }
    for class in ["Stuff v1.40", "Stuff v1.0a\0Stuff v1.4"] {
        let mut text = markers.to_vec();
        text.extend(class.bytes().chain([0]));
        fs::write(&host, pe_bytes(&text)).unwrap();
        assert!(matches!(
            identify(&dir.0, &cancel),
            Err(Error::UnknownScheme(_))
        ));
    }
    fs::write(&host, pe_bytes(b"Stuff v1.4\0")).unwrap();
    assert!(identify(&dir.0, &cancel).unwrap().is_none());
    for (name, class) in [("host.exe", "Stuff v1.0a"), ("other.exe", "Stuff v1.4")] {
        let mut text = markers.to_vec();
        text.extend(class.bytes().chain([0]));
        fs::write(dir.0.join(name), pe_bytes(&text)).unwrap();
    }
    assert!(matches!(
        identify(&dir.0, &cancel),
        Err(Error::UnknownScheme(_))
    ));
}
