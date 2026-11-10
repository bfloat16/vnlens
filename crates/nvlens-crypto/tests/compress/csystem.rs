use super::*;
#[test]
fn dictionary_initialization_overlap_and_bounds() {
    let bytes = [7, b'A', b'B', b'C', 0xee, 0xf3];
    assert_eq!(decompress(&bytes, 9).ok(), Some(b"ABCABCABC".to_vec()));
    assert_eq!(decompress(&[0, 0, 0], 3).ok(), Some(vec![0; 3]));
    for end in 0..bytes.len() {
        assert!(decompress(&bytes[..end], 9).is_err());
    }
    assert!(decompress(&bytes, 8).is_err());
}
