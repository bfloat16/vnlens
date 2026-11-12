#![allow(clippy::unwrap_used)]

use super::*;
use vnlens_io::BinaryWriter;

fn view(bytes: Vec<u8>) -> Arc<ArcView> {
    Arc::new(ArcView::from_bytes("script.mpk".into(), bytes.into()))
}

fn fixture() -> Vec<u8> {
    let mut bytes = vec![0; 0x40 + 2 * 0x100 + 8];
    bytes[..4].copy_from_slice(b"MPK\0");
    BinaryWriter::u32_le(0x20000, &mut bytes[4..]);
    BinaryWriter::u32_le(2, &mut bytes[8..]);
    // Slot 0: empty hole (retained in index table, skipped in entries)
    // Slot 1: stored entry at 0x240, size 4
    let second = 0x40 + 0x100;
    BinaryWriter::u32_le(1, &mut bytes[second + 4..]);
    BinaryWriter::u64_le(0x240, &mut bytes[second + 8..]);
    BinaryWriter::u64_le(4, &mut bytes[second + 16..]);
    BinaryWriter::u64_le(4, &mut bytes[second + 24..]);
    bytes[second + 0x20..second + 0x20 + 8].copy_from_slice(b"main.scx");
    bytes[0x240..0x248].copy_from_slice(b"SC3\0TAIL");
    bytes
}

#[test]
fn skips_empty_slots_mounts_lazily_and_rejects_invalid_storage() -> Result<()> {
    let archive = Mpk.open(&view(fixture()), &ArchiveOptions::default())?;
    assert_eq!(archive.entries().len(), 1);
    let entry = &archive.entries()[0];
    assert_eq!(entry.name, "main.scx");
    assert_eq!(entry.offset, 0x240);
    assert_eq!(entry.size, 4);
    assert!(matches!(
        archive.open_entry(entry)?,
        Cow::Borrowed(b"SC3\0")
    ));
    let source = archive
        .open_entry_source(entry)?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(&*source.read_at(0, 4)?, b"SC3\0");

    // Overlap with index
    let mut overlap = fixture();
    BinaryWriter::u64_le(0x100, &mut overlap[0x140 + 8..]);
    assert!(matches!(
        Mpk.open(&view(overlap), &ArchiveOptions::default()),
        Err(Error::Corrupt { .. })
    ));

    // Out-of-bounds placement
    let mut oob = fixture();
    BinaryWriter::u64_le(99, &mut oob[0x140 + 16..]);
    BinaryWriter::u64_le(99, &mut oob[0x140 + 24..]);
    assert!(matches!(
        Mpk.open(&view(oob), &ArchiveOptions::default()),
        Err(Error::Corrupt { .. })
    ));

    // Unsupported flags
    let mut flags = fixture();
    BinaryWriter::u32_le(1, &mut flags[0x140..]);
    assert!(matches!(
        Mpk.open(&view(flags), &ArchiveOptions::default()),
        Err(Error::Unsupported(_))
    ));
    Ok(())
}
