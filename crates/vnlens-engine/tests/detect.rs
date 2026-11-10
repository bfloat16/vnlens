#![allow(clippy::unwrap_used)]

use super::*;
use std::{fs, sync::atomic::AtomicU64};
use vnlens_core::{ResourceOrigin, ResourceRoute};
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
        "vnlens-engine-{}-{}-{}",
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

#[test]
fn emote_attaches_to_host_and_never_identifies_an_engine() {
    let dir = temp();
    let cancel = AtomicBool::new(false);
    fs::create_dir(dir.0.join("plugin")).unwrap();
    fs::write(
        dir.0.join("plugin/psbfile.dll"),
        pe_bytes(b"PSBFile\0psbfile.dll\0"),
    )
    .unwrap();
    assert!(identify(&dir.0, &cancel).unwrap().is_none());
    fs::write(dir.0.join("host.exe"), pe_bytes(b"AdvHD\0WillPlus\0")).unwrap();
    let game = identify(&dir.0, &cancel).unwrap().unwrap();
    assert_eq!(game.engine, Engine::Will);
    assert_eq!(archive_tag(&game, "data.arc"), "arc/willv2");
    assert_eq!(archive_tag(&game, "body.psb"), "psb/emote-resources");
    assert_eq!(
        archive_tag(&game, "pack_info.psb.m"),
        "psb/emote-archive-info"
    );
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

fn archive_tag(game: &Identification, name: &str) -> &'static str {
    match game.resource_route(name, ResourceOrigin::File, &[]) {
        ResourceRoute::Archive(route) => route.tag,
        _ => "missing archive route",
    }
}
#[test]
fn softpal_pe_evidence_and_routing() {
    let cancel = AtomicBool::new(false);
    let soft = temp();
    fs::write(
        soft.0.join("host.exe"),
        pe_bytes(b"PalFileCreate\0Script.src\0Point.dat\0"),
    )
    .unwrap();
    let game = identify(&soft.0, &cancel).unwrap().unwrap();
    assert_eq!(game.engine, Engine::Softpal);
    assert_eq!(archive_tag(&game, "data.pac"), "pac/softpal");
    assert_eq!(
        game.resource_route("FACE.PGD", ResourceOrigin::File, &[]),
        ResourceRoute::Image("pgd/softpal")
    );
    assert!(!matches!(
        game.resource_route("Arc04.dat", ResourceOrigin::File, &[]),
        ResourceRoute::Archive(_)
    ));
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
