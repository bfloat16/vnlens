use super::*;
use nvlens_io::BinaryWriter;
fn stream(size: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = b"acp\0\0\0\0\0".to_vec();
    BinaryWriter::u32_be(size, &mut out[4..]);
    out.extend_from_slice(payload);
    out
}
#[test]
fn literals_overlap_width_changes_reset_and_empty_output() -> io::Result<()> {
    // 9-bit codes: A, B, dictionary[0], dictionary[2], end.
    assert_eq!(
        unpack(&stream(7, &[0x20, 0x90, 0xa0, 0x70, 0x58, 0x00]))?,
        b"ABABABA"
    );
    assert_eq!(unpack(&stream(0, &[0x80, 0x00]))?, b"");
    // A, widen, B (10 bits), reset (10 bits), C (9 bits), end.
    assert_eq!(
        unpack(&stream(3, &[0x20, 0xc0, 0x44, 0x24, 0x08, 0x87, 0x00]))?,
        b"ABC"
    );
    Ok(())
}
#[test]
fn rejects_undefined_matches_truncation_and_size_mismatch() {
    for data in [
        stream(1, &[0x81, 0x80]),
        stream(1, &[0x80, 0]),
        stream(0, &[0x20, 0xc0, 0]),
        stream(1, &[0x20]),
    ] {
        assert!(unpack(&data).is_err());
    }
    assert!(unpack(b"acp\0").is_err());
}
