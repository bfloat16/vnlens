use super::*;
use nvlens_io::BinaryWriter;
fn u32_word(out: &mut Vec<u8>, value: u32) {
    let mut bytes = [0; 4];
    BinaryWriter::u32_le(value, &mut bytes);
    out.extend(bytes);
}
#[test]
fn resource_index_retains_u64_offsets_and_vacant_ordinals() -> Result<()> {
    let mut bytes = Vec::new();
    for v in [1, 3] {
        u32_word(&mut bytes, v);
    }
    for (size, offset) in [(0, 0), (5, 0x1_0000_0001), (4, 0x2_0000_0000)] {
        u32_word(&mut bytes, 0);
        u32_word(&mut bytes, size);
        let mut word = [0; 8];
        BinaryWriter::u64_le(offset, &mut word);
        bytes.extend(word);
    }
    u32_word(&mut bytes, 0);
    u32_word(&mut bytes, 0);
    let tables = resources(&bytes)?;
    assert_eq!(tables.len(), 1);
    let entries = &tables[0].entries;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "10000001.cimg");
    assert_eq!(entries[1].offset, 0x2_0000_0000);
    for end in 0..bytes.len() {
        assert!(resources(&bytes[..end]).is_err());
    }
    Ok(())
}
#[test]
fn decimal_lengths_are_format_bounded() -> Result<()> {
    assert_eq!(decimal(&[255, 255, 255, 255, 255, 0x7e, 0x7d, 0x7c])?, 123);
    assert_eq!(decimal(&[0x76; 8])?, 99_999_999);
    assert!(decimal(&[0]).is_err());
    Ok(())
}

#[test]
fn arc_music_storage_includes_loop_header_without_reading_payload() -> Result<()> {
    let mut row = Vec::new();
    for value in [23, 7, 100, 100, 0x1000] {
        u32_word(&mut row, value);
    }
    row.extend(b"u0");
    u32_word(&mut row, u32::MAX);
    row.push(0);
    let mut packed = Vec::new();
    for chunk in row.chunks(8) {
        packed.push(255);
        packed.extend(chunk);
    }
    let mut bytes = Vec::new();
    for value in [row.len(), packed.len()] {
        bytes.extend(format!("{value:08}").bytes().map(|b| (b - b'0') ^ 127));
    }
    bytes.extend(packed);
    let source: Arc<[u8]> = bytes.into();
    // Only the index exists: mounting must not consult any audio header.
    let entries = arc(&source)?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0.name, "00000007.u0");
    assert_eq!(entries[0].0.offset, 0x1000);
    assert_eq!(entries[0].0.size, 112);
    assert_eq!(entries[0].0.kind, ResourceKind::Audio);
    assert!(entries[0].0.packed.is_none());
    Ok(())
}
