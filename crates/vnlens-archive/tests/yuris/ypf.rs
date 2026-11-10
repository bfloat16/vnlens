#![allow(clippy::unwrap_used)]

use super::*;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use vnlens_io::BinaryWriter;
struct TestFile(std::path::PathBuf);
impl Drop for TestFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn file(bytes: &[u8]) -> TestFile {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "vnlens-ypf-{}-{}-{}.ypf",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, bytes).unwrap();
    TestFile(path)
}
const RECORDS: &[(&str, &[u8], u8)] = &[("bad.ybn", b"x", 1), ("folder/ok.txt", b"hello", 0)];
fn fixture(records: &[(&str, &[u8], u8)]) -> Vec<u8> {
    let index_end = 32
        + records
            .iter()
            .map(|(name, _, _)| 27 + name.len())
            .sum::<usize>();
    let mut bytes = vec![0; 32];
    bytes[..4].copy_from_slice(b"YPF\0");
    for (offset, value) in [
        (4, 0x1ee),
        (8, records.len() as u32),
        (12, index_end as u32),
    ] {
        BinaryWriter::u32_le(value, &mut bytes[offset..]);
    }
    let mut offset = index_end as u64;
    for (name, data, packed) in records {
        let mut record = vec![0; 27 + name.len()];
        BinaryWriter::u32_le(murmur2::hash(name.as_bytes(), 0), &mut record);
        let mut length = name.len() as u8;
        for &(a, b) in LENGTH_SWAPS {
            if length == a {
                length = b;
                break;
            }
            if length == b {
                length = a;
                break;
            }
        }
        record[4] = !length;
        for (out, &byte) in record[5..5 + name.len()].iter_mut().zip(name.as_bytes()) {
            *out = byte ^ 0xa7;
        }
        let at = 5 + name.len();
        record[at] = 0;
        record[at + 1] = *packed;
        BinaryWriter::u32_le(data.len() as u32, &mut record[at + 2..]);
        BinaryWriter::u32_le(data.len() as u32, &mut record[at + 6..]);
        BinaryWriter::u64_le(offset, &mut record[at + 10..]);
        BinaryWriter::u32_le(murmur2::hash(data, 0), &mut record[at + 18..]);
        offset += data.len() as u64;
        bytes.extend(record);
    }
    for (_, data, _) in records {
        bytes.extend_from_slice(data);
    }
    bytes
}
#[test]
fn index_mount_is_lazy_and_identified_name_key_is_verified() {
    let bytes = fixture(RECORDS);
    let file = file(&bytes);
    let archive =
        YpfArchive::open(Arc::new(ArcView::open(&file.0).unwrap()), [0; 4], 0xa7).unwrap();
    assert_eq!(archive.entries()[1].name, "folder/ok.txt");
    assert!(
        archive
            .open_entry_source(&archive.entries()[0])
            .unwrap()
            .is_none()
    );
    let source = archive
        .open_entry_source(&archive.entries()[1])
        .unwrap()
        .unwrap();
    assert_eq!(&*source.read_at(1, 3).unwrap(), b"ell");
    assert_eq!(&*source.read_at(0, 5).unwrap(), b"hello");
    assert_eq!(
        &*archive.open_entry(&archive.entries()[1]).unwrap(),
        b"hello"
    );
    assert!(archive.open_entry(&archive.entries()[0]).is_err());
    assert_eq!(
        &*archive.open_entry_raw(&archive.entries()[0]).unwrap(),
        b"x"
    );
    drop(archive);
}
#[test]
fn rejects_truncated_index_and_out_of_range_64_bit_offsets() {
    let mut bytes = fixture(RECORDS);
    let first_offset = 32 + 5 + "bad.ybn".len() + 10;
    BinaryWriter::u64_le(0x1_0000_0000, &mut bytes[first_offset..]);
    let file = file(&bytes);
    assert!(YpfArchive::open(Arc::new(ArcView::open(&file.0).unwrap()), [0; 4], 0xa7).is_err());
    fs::write(&file.0, &bytes[..40]).unwrap();
    assert!(YpfArchive::open(Arc::new(ArcView::open(&file.0).unwrap()), [0; 4], 0xa7).is_err());
}

#[test]
fn virtual_paths_read_only_the_script_list_and_preserve_entry_names() {
    let path = b"story\\main.yst";
    let mut table = vec![0; 20];
    table[..4].copy_from_slice(b"YSTL");
    BinaryWriter::u32_le(0x1ee, &mut table[4..]);
    BinaryWriter::u32_le(1, &mut table[8..]);
    BinaryWriter::u32_le(3, &mut table[12..]);
    BinaryWriter::u32_le(path.len() as u32, &mut table[16..]);
    table.extend_from_slice(path);
    table.resize(table.len() + 20, 0);
    let mut bytes = fixture(&[
        ("ysbin/yst00003.ybn", b"x", 1),
        ("ysbin/yst00004.ybn", b"other", 0),
        ("ysbin/yst_list.ybn", &table, 0),
    ]);
    let file = file(&bytes);
    let archive =
        YpfArchive::open(Arc::new(ArcView::open(&file.0).unwrap()), [0; 4], 0xa7).unwrap();
    assert_eq!(archive.entries()[0].name, "ysbin/yst00003.ybn");
    assert_eq!(
        archive.virtual_paths().unwrap(),
        [(0, "story\\main.yst".into())]
    );
    assert!(archive.open_entry(&archive.entries()[0]).is_err());
    drop(archive);
    let table_offset = bytes.len() - table.len();
    bytes[table_offset] = b'X';
    fs::write(&file.0, bytes).unwrap();
    let archive =
        YpfArchive::open(Arc::new(ArcView::open(&file.0).unwrap()), [0; 4], 0xa7).unwrap();
    assert_eq!(archive.entries().len(), 3);
    assert!(archive.virtual_paths().is_err());
}
