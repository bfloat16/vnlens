#![allow(clippy::unwrap_used)]

use super::*;
use nvlens_io::BinaryWriter;
use std::{fs, sync::atomic::AtomicU64};

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn temp() -> Temp {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "nvlens-engine-{}-{}-{}",
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
    assert_eq!(game.route("BG.MPK").unwrap().tag, "mpk/propeller");
    let movie = dir.0.join("ma.mpk");
    let mut header = [0; 12];
    BinaryWriter::u32_le(0xba01_0000, &mut header);
    fs::write(&movie, header).unwrap();
    assert_eq!(
        game.resource_kind_for_path(&movie),
        nvlens_core::ResourceKind::Video
    );
    assert!(game.route_path(&movie).is_none());
    let package = dir.0.join("m.mpk");
    BinaryWriter::u32_le(8, &mut header);
    fs::write(&package, header).unwrap();
    assert!(game.route_path(&package).is_some());
    assert_eq!(game.script_format_for("system.MSC"), Some("msc/propeller"));
    assert!(game.route("data.arc").is_none());
    assert!(game.script_format_for("image.mgr").is_none());
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
    assert_eq!(game.route("random.arc").unwrap().tag, "arc/willv2");
    assert!(game.route("Scripts.ypf").is_none());
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
    assert_eq!(game.route("data.arc").unwrap().tag, "arc/willv2");
    assert_eq!(game.route("body.psb").unwrap().tag, "psb/emote-resources");
    assert_eq!(
        game.route("pack_info.psb.m").unwrap().tag,
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
    assert_eq!(game.route("DATA.XP3").unwrap().tag, "xp3/krkr");
    assert!(game.resource_options().numbers.is_empty());
    assert_eq!(game.script_format_for("scene.ks"), Some("script/krkr"));
    assert!(game.route("other.arc").is_none());
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
