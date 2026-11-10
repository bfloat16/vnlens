#![allow(clippy::unwrap_used)]

use super::*;
use vnlens_io::BinaryWriter;

fn options() -> vnlens_core::ArchiveOptions {
    let mut options = vnlens_core::ArchiveOptions::default();
    options.keys.insert(
        "scramble",
        vnlens_core::Secret::new(b"11f32b0d98cfe8395fe4deeb75fff578".to_vec()),
    );
    options
}

#[test]
fn mounts_index_and_decodes_only_requested_entries() {
    let dir = std::env::temp_dir().join(format!(
        "vnlens-fpd-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("fixture.fpd");
    let base = vnlens_bin::load(keys::ages_mk2::SCRAMBLE_BASE).unwrap();
    let stream = Keystream::new(&base, b"11f32b0d98cfe8395fe4deeb75fff578").unwrap();
    let names = b"good.bin\0bad.bin\0";
    let index_size = HEADER_SIZE as usize + ENTRY_SIZE * 2 + names.len();
    let mut bytes = vec![0; index_size];
    bytes[..4].copy_from_slice(MAGIC);
    BinaryWriter::u32_be(1, &mut bytes[4..8]);
    BinaryWriter::u64_be(2, &mut bytes[8..16]);
    BinaryWriter::u64_be(index_size as u64, &mut bytes[16..24]);
    for (i, record) in [[0u64, 0, 2, 0], [9, 2, 3, 10]].iter().enumerate() {
        for (j, &word) in record.iter().enumerate() {
            let offset = HEADER_SIZE as usize + i * ENTRY_SIZE + j * 8;
            BinaryWriter::u64_be(word, &mut bytes[offset..offset + 8]);
        }
    }
    bytes[HEADER_SIZE as usize + 2 * ENTRY_SIZE..].copy_from_slice(names);
    stream.descramble(&mut bytes[HEADER_SIZE as usize..], 0);
    let mut good = *b"ok";
    stream.descramble(&mut good, 0);
    bytes.extend(good);
    let mut bad = *b"bad";
    stream.descramble(&mut bad, 0);
    bytes.extend(bad);
    std::fs::write(&path, &bytes).unwrap();
    let view = Arc::new(ArcView::open(&path).unwrap());
    let archive = FpdArc.open(&view, &options()).unwrap();
    assert_eq!(archive.entries().len(), 2);
    assert_eq!(
        archive.open_entry(&archive.entries()[0]).unwrap().as_ref(),
        b"ok"
    );
    assert_eq!(
        archive
            .open_entry_raw(&archive.entries()[1])
            .unwrap()
            .as_ref(),
        &bad
    );
    assert!(archive.open_entry(&archive.entries()[1]).is_err());
    drop(archive);
    drop(view);
    std::fs::write(&path, b"FPD\0").unwrap();
    let view = Arc::new(ArcView::open(&path).unwrap());
    assert!(FpdArc.open(&view, &options()).is_err());
    drop(view);
    std::fs::write(&path, b"other").unwrap();
    let view = Arc::new(ArcView::open(&path).unwrap());
    assert!(FpdArc.open(&view, &options()).is_err());
    drop(view);
    std::fs::remove_dir_all(dir).unwrap();
}
