#![allow(clippy::unwrap_used)]

use super::*;
use vnlens_io::BinaryWriter;

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn temp() -> Temp {
    let path = std::env::temp_dir().join(format!(
        "vnlens-exhibit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&path).unwrap();
    Temp(path)
}
fn index(volume: u32) -> Vec<u8> {
    let words = [
        0x5346_6941,
        0x50000,
        0x2a,
        1,
        0x1000000,
        volume,
        123,
        125,
        3,
        0,
        3,
        0,
        0,
        100,
        50,
    ];
    let mut bytes = vec![0; words.len() * 4];
    for (i, value) in words.into_iter().enumerate() {
        BinaryWriter::u32_le(value, &mut bytes[i * 4..]);
    }
    bytes
}

#[test]
fn split_hex_volume_is_lazy_and_bad_neighbor_does_not_block_good_entry() {
    let dir = temp();
    let path = dir.0.join("res2a00.grp");
    std::fs::write(&path, index(10)).unwrap();
    let view = Arc::new(ArcView::open(&path).unwrap());
    let archive = Grp.open(&view, &ArchiveOptions::default()).unwrap();
    assert_eq!(archive.entries().len(), 2);
    assert_eq!(archive.entries()[0].name, "00123");
    // Neither mapping nor payload validation occurs at mount/list time.
    std::fs::write(dir.0.join("res2a0a.grp"), b"abc").unwrap();
    assert!(matches!(
        archive.open_entry(&archive.entries()[0]).unwrap(),
        Cow::Borrowed(b"abc")
    ));
    assert!(archive.open_entry(&archive.entries()[1]).is_err());
    let view = Arc::new(ArcView::open(dir.0.join("res2a0a.grp")).unwrap());
    assert_eq!(
        Grp.open(&view, &ArchiveOptions::default())
            .unwrap()
            .entries()
            .len(),
        2
    );
}

#[test]
fn truncated_index_is_rejected_without_reading_data() {
    let dir = temp();
    let path = dir.0.join("res2a00.grp");
    let mut bytes = index(1);
    bytes.pop();
    std::fs::write(&path, bytes).unwrap();
    let view = Arc::new(ArcView::open(path).unwrap());
    assert!(Grp.open(&view, &ArchiveOptions::default()).is_err());
}
