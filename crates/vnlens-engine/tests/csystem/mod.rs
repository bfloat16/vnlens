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
        "vnlens-engine-csystem-{}-{}-{}",
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
fn csystem_pe_evidence_legacy_routing_and_missing_key() {
    let cancel = AtomicBool::new(false);
    let cs = temp();
    fs::write(
        cs.0.join("host.exe"),
        pe_bytes(b".?AVArchiveMap@@\0Arc00.dat\0Arc01.dat\0Arc04.dat\0Arc03.dat\0Arc06.dat\0"),
    )
    .unwrap();
    assert!(matches!(
        identify(&cs.0, &cancel),
        Err(Error::UnknownScheme(_))
    ));
    let markers = b".?AVArchiveMap@@\0Arc00.dat\0Data%03d.dat\0";
    fs::write(cs.0.join("host.exe"), pe_bytes(markers)).unwrap();
    assert!(matches!(
        identify(&cs.0, &cancel),
        Err(Error::UnknownScheme(_))
    ));
    let mut text = markers.to_vec();
    text.extend_from_slice(b"00000000-0000-0000-0000-000000000000 Copyright 2004 Cyberworks \"TinkerBell\"., all rights reserved.\0");
    fs::write(cs.0.join("host.exe"), pe_bytes(&text)).unwrap();
    let game = identify(&cs.0, &cancel).unwrap().unwrap();
    assert_eq!(game.engine, Engine::Csystem);
    assert_eq!(archive_tag(&game, "Arc04.dat"), "dat/csystem");
    assert_eq!(
        game.resource_route(
            "00000001.a0",
            ResourceOrigin::Entry(vnlens_core::ResourceKind::Script),
            &[]
        ),
        ResourceRoute::Script("script/csystem")
    );
    assert!(!matches!(
        game.resource_route("bg.pac", ResourceOrigin::File, &[]),
        ResourceRoute::Archive(_)
    ));
    assert!(!format!("{game:?}").contains("00000000-0000"));
    assert_eq!(game.options.numbers.get("csystem_legacy"), Some(&0));
    let mut old =
        b".?AVArchiveMap@@\0Arc00.dat\0Arc01.dat\0Arc04.dat\0Arc03.dat\0Arc06.dat\0".to_vec();
    old.extend_from_slice(b"00000000-0000-0000-0000-000000000000 Copyright 2004 Cyberworks \"TinkerBell\"., all rights reserved.\0");
    fs::write(cs.0.join("host.exe"), pe_bytes(&old)).unwrap();
    let old = identify(&cs.0, &cancel).unwrap().unwrap();
    assert_eq!(old.options.numbers.get("csystem_legacy"), Some(&1));
    for ext in ["b0", "n0", "o0"] {
        assert_eq!(
            old.resource_route(&format!("00000001.{ext}"), ResourceOrigin::File, b"a\xef"),
            ResourceRoute::Image("image-legacy/csystem")
        );
    }
    assert_eq!(
        old.resource_route("00000001.c0", ResourceOrigin::File, &[]),
        ResourceRoute::Script("animation-legacy/csystem")
    );
}
