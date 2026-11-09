#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn all_literals_roundtrip() {
    // One control byte covering eight literals, all bits set.
    let mut packed = vec![0xFFu8];
    packed.extend_from_slice(b"ABCDEFGH");
    let out = decompress(&packed, 8).unwrap();
    assert_eq!(&out, b"ABCDEFGH");
}

#[test]
fn back_reference_repeats() {
    // Write 'A', then copy it via one back-reference.
    // Control byte: bit0=1 literal 'A'; bit1=0 match.
    // 'A' goes to frame[1], write pointer -> 2. Match offset=1 (reads
    // frame[1]='A'), length = 2 + 3 = 5.
    let hi = 0x00u8;
    let lo = 0x13u8; // offset low nibble = 1 -> offset = 1; length = 2 + 3 = 5
    let packed = vec![0b0000_0001, b'A', hi, lo];
    let out = decompress(&packed, 6).unwrap();
    assert_eq!(&out, b"AAAAAA");
}

#[test]
fn truncated_input_errors() {
    let packed = vec![0xFF, b'A'];
    assert!(matches!(
        decompress(&packed, 8),
        Err(CompressError::Truncated { .. })
    ));
}
