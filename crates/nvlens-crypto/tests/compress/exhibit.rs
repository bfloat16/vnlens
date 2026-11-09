#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn lzss_ring_overlap_and_zero_history() {
    assert_eq!(lzss(&[1, b'A', 0xee, 0xf2], 6).unwrap(), b"AAAAAA");
    assert_eq!(lzss(&[0, 0, 0], 3).unwrap(), [0; 3]);
    assert!(lzss(&[0, 0], 3).is_err());
    assert!(lzss(&[0, 0, 0], 2).is_err());
}

#[test]
fn gyu_interleaved_literals_short_and_long_matches() {
    assert_eq!(
        gyu(&[0, 0, 0, 0, b'A', 0x80, b'B', 255], 4).unwrap(),
        b"ABBB"
    );
    assert_eq!(
        gyu(&[0, 0, 0, 0, b'A', 0x40, 255, 249], 4).unwrap(),
        b"AAAA"
    );
    assert!(gyu(&[0, 0, 0, 0, b'A', 0, 0], 3).is_err());
    assert!(gyu(&[0, 0, 0, 0, b'A', 0x80], 3).is_err());
}
