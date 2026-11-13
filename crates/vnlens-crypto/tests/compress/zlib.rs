#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn known_zlib_vector_and_declared_length() {
    let input = [120, 156, 203, 72, 205, 201, 201, 7, 0, 6, 44, 2, 21];
    assert!(has_header(&input));
    for bytes in [&[][..], &[0x78][..], &[0x78, 0x9d][..], &[0x89, 0x1c][..]] {
        assert!(!has_header(bytes));
    }
    assert_eq!(inflate_with_limit(&input, 5).unwrap(), b"hello");
    assert!(validate(&input, 5).is_ok());
    for end in 0..input.len() {
        assert!(validate(&input[..end], 5).is_err());
    }
    assert!(matches!(
        inflate_with_limit(&input, 4),
        Err(CompressError::OutputTooLarge { .. })
    ));
    let mut damaged = input;
    damaged[12] ^= 1;
    assert!(inflate(&damaged).is_err());
    assert!(validate(&damaged, 5).is_err());
}

#[test]
fn framing_validation_spans_multiple_output_chunks() {
    use std::io::Write;
    let bytes = vec![b'a'; 24577];
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&bytes).unwrap();
    let compressed = encoder.finish().unwrap();
    assert!(validate(&compressed, bytes.len()).is_ok());
    assert!(validate(&compressed, bytes.len() - 1).is_err());
}
