#![allow(clippy::unwrap_used)]

use super::*;
use crate::identify;
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
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
        "vnlens-engine-mages-{}-{}-{}",
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
fn mages_scopes_dialogue_directory_on_direct_or_nested_entry() {
    let dir = temp();
    let cancel = AtomicBool::new(false);
    let data_mb = dir.0.join("DataMB");
    fs::create_dir(&data_mb).unwrap();
    fs::write(
        dir.0.join("host.exe"),
        pe_bytes(b"mgs::\0.scx\0.msb\0DataMB\0"),
    )
    .unwrap();
    let game = Arc::new(identify(&dir.0, &cancel).unwrap().unwrap());
    assert_eq!(game.engine, Engine::Mages);
    assert_eq!(
        game.resource_options()
            .numbers
            .get("mages_dialogue_extension"),
        None
    );
    let scoped = game.for_directory(&data_mb, &cancel).unwrap();
    assert_eq!(
        scoped
            .resource_options()
            .numbers
            .get("mages_dialogue_extension"),
        Some(&1)
    );
    let direct = identify(&data_mb, &cancel).unwrap().unwrap();
    assert_eq!(
        direct
            .resource_options()
            .numbers
            .get("mages_dialogue_extension"),
        Some(&1)
    );
}
