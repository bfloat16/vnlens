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
    let path = std::env::temp_dir().join(format!("vnlens-tamsoft-{}-{stamp}", std::process::id()));
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
fn independent_pe_evidence_conflicts_and_cancellation() {
    let dir = temp();
    let cancel = AtomicBool::new(false);
    fs::write(
        dir.0.join("data.cat"),
        b"Tamlib::DataTexture::Impl::construct\0Tamlib::TamTexture::Impl::construct\0",
    )
    .unwrap();
    assert!(identify(&dir.0, &cancel).unwrap().is_none());
    fs::write(
        dir.0.join("game.exe"),
        image(b"Tamlib::DataTexture::Impl::construct\0"),
    )
    .unwrap();
    assert!(identify(&dir.0, &cancel).unwrap().is_none());
    fs::write(
        dir.0.join("game.exe"),
        image(b"Tamlib::DataTexture::Impl::construct\0Tamlib::TamTexture::Impl::construct\0"),
    )
    .unwrap();
    assert_eq!(
        identify(&dir.0, &cancel).unwrap().unwrap().engine,
        Engine::Tamsoft
    );
    fs::write(
        dir.0.join("other.exe"),
        image(b"EntisGLS_GameWindow\0ERISAArchive\0"),
    )
    .unwrap();
    assert!(matches!(
        identify(&dir.0, &cancel),
        Err(vnlens_core::Error::Unsupported(_))
    ));
    assert!(matches!(
        identify(&dir.0, &AtomicBool::new(true)),
        Err(vnlens_core::Error::Cancelled)
    ));
}

#[test]
fn native_containers_and_models_route_while_scripts_stay_unrouted() {
    let game = Identification {
        root: Default::default(),
        engine: Engine::Tamsoft,
        evidence: "Fixture".into(),
        files: Default::default(),
        options: ArchiveOptions::default(),
        middleware: Vec::new(),
        compose_pimg: Default::default(),
    };
    let origin = ResourceOrigin::Entry(ResourceKind::Unknown);
    for name in [
        "Binary/Adv/MainScript.cat",
        "C:/Game/AddContents/Binary/Adv/AddScript.cat",
    ] {
        assert_eq!(
            game.resource_route(name, ResourceOrigin::File, &[]),
            ResourceRoute::Other(ResourceKind::Script)
        );
    }
    for (name, tag) in [
        ("UI/AdvUI.CAT", "cat/tamsoft"),
        ("THR.semb", "semb/tamsoft"),
    ] {
        assert!(
            matches!(game.resource_route(name, origin, &[]), ResourceRoute::Archive(a) if a.tag==tag)
        );
    }
    let mut cat = [0; 24];
    for (at, value) in [(0, 1), (4, 1), (12, 32), (16, 64)] {
        BinaryWriter::u32_le(value, &mut cat[at..]);
    }
    assert!(
        matches!(game.resource_route("0", origin, &cat), ResourceRoute::Archive(a) if a.tag=="cat/tamsoft")
    );
    let mut array = [0; 16];
    for (at, value) in [(0, 16), (4, 1), (8, 256)] {
        BinaryWriter::u32_le(value, &mut array[at..]);
    }
    assert!(
        matches!(game.resource_route("1", origin, &array), ResourceRoute::Archive(a) if a.tag=="textures/tamsoft")
    );
    for words in [[2, 3, 0, 64], [24, 3, u32::MAX, 0]] {
        let mut data = [0; 64];
        for (chunk, word) in data.chunks_exact_mut(4).zip(words) {
            BinaryWriter::u32_le(word, chunk);
        }
        assert_eq!(
            game.resource_route("0", origin, &data),
            ResourceRoute::Other(ResourceKind::Unknown)
        );
    }
    for name in [
        "Adv.bin",
        "texture.foo",
        "script.ttb",
        "mesh.obj",
        "other.xp3",
    ] {
        assert_eq!(
            game.resource_route(name, origin, b"DDS "),
            ResourceRoute::Other(ResourceKind::Unknown)
        );
    }
    assert_eq!(
        game.resource_route("model.tmd", origin, &[]),
        ResourceRoute::Model("tmd/tamsoft")
    );
    assert_eq!(
        game.resource_route("1", origin, b"tmd0"),
        ResourceRoute::Model("tmd/tamsoft")
    );
    assert_eq!(
        game.resource_route("0", origin, b"DDS "),
        ResourceRoute::Image("dds")
    );
    assert_eq!(
        game.resource_route("0", origin, &[]),
        ResourceRoute::Other(ResourceKind::Unknown)
    );
}
