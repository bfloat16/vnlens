#![allow(clippy::unwrap_used)]

use super::*;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use vnlens_core::ArchiveOptions;
use vnlens_io::BinaryWriter;

struct TestDir(std::path::PathBuf);
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn build_arc(records: &[(&str, &[u8])]) -> Vec<u8> {
    let mut index = Vec::new();
    let mut data = Vec::new();
    for &(name, payload) in records {
        let mut header = [0u8; 8];
        BinaryWriter::u32_le(u32::try_from(payload.len()).unwrap(), &mut header[..4]);
        BinaryWriter::u32_le(u32::try_from(data.len()).unwrap(), &mut header[4..8]);
        index.extend_from_slice(&header);
        for unit in name.encode_utf16().chain(std::iter::once(0)) {
            let mut word = [0u8; 2];
            BinaryWriter::u16_le(unit, &mut word);
            index.extend_from_slice(&word);
        }
        data.extend_from_slice(payload);
    }
    let mut out = vec![0u8; 8];
    BinaryWriter::u32_le(u32::try_from(records.len()).unwrap(), &mut out[..4]);
    BinaryWriter::u32_le(u32::try_from(index.len()).unwrap(), &mut out[4..8]);
    out.extend_from_slice(&index);
    out.extend_from_slice(&data);
    out
}

#[test]
fn mounts_lazily_and_applies_entry_transforms() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = TestDir(std::env::temp_dir().join(format!(
        "vnlens-will-arc-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    fs::create_dir_all(&dir.0).unwrap();

    let ws2_plain = b"script\x01\x02\x04\x08\x10\x20\x40\x80";
    let ws2_stored: Vec<u8> = ws2_plain
        .iter()
        .enumerate()
        .map(|(i, b)| if i < 6 { b.rotate_left(2) } else { *b })
        .collect();
    let psp_valid = [3, 0, 0, 0, 0b0000_0111, b'A', b'B', b'C'];
    let bytes = build_arc(&[
        ("scene.ws2", &ws2_stored),
        ("ok.psp", &psp_valid),
        ("corrupt.psp", b"short"),
        ("raw.bin", b"raw"),
    ]);

    let rio_path = dir.0.join("Rio.arc");
    fs::write(&rio_path, &bytes).unwrap();
    let archive = WillV2Arc
        .open(
            &Arc::new(ArcView::open(&rio_path).unwrap()),
            &ArchiveOptions::default(),
        )
        .unwrap();
    let entries = archive.entries();
    assert_eq!(entries.len(), 4);
    assert_eq!(&*archive.open_entry(&entries[0]).unwrap(), ws2_plain);
    assert_eq!(&*archive.open_entry_raw(&entries[0]).unwrap(), &ws2_stored);
    assert_eq!(&*archive.open_entry(&entries[1]).unwrap(), b"ABC");
    assert!(archive.open_entry(&entries[2]).is_err());
    assert_eq!(&*archive.open_entry(&entries[3]).unwrap(), b"raw");

    let model_path = dir.0.join("CharaModel.arc");
    fs::write(&model_path, &bytes).unwrap();
    let model_arc = WillV2Arc
        .open(
            &Arc::new(ArcView::open(&model_path).unwrap()),
            &ArchiveOptions::default(),
        )
        .unwrap();
    assert_eq!(
        &*model_arc.open_entry(&model_arc.entries()[0]).unwrap(),
        &ws2_stored
    );

    let truncated_path = dir.0.join("truncated.arc");
    fs::write(&truncated_path, &bytes[..12]).unwrap();
    assert!(
        WillV2Arc
            .open(
                &Arc::new(ArcView::open(&truncated_path).unwrap()),
                &ArchiveOptions::default(),
            )
            .is_err()
    );
}
