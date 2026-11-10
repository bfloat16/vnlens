use super::*;
#[test]
fn literals_overlap_and_truncation() {
    let bytes = [2, 3, b'a', b'b', b'c', 0x3a, 0];
    assert_eq!(decompress(&bytes, 9).ok(), Some(b"abcabcabc".to_vec()));
    for end in 0..bytes.len() {
        assert!(decompress(&bytes[..end], 9).is_err());
    }
    assert!(decompress(&[1, 8, 0], 4).is_err());
    assert!(decompress(&bytes, 8).is_err());
    let bytes = [2, 3, b'a', b'b', b'c', 0x30, 0, 32];
    assert_eq!(decompress(&bytes, 39).ok(), Some(b"abc".repeat(13)));
}
