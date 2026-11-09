#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn known_zlib_vector_and_declared_length() {
    let input = [120, 156, 203, 72, 205, 201, 201, 7, 0, 6, 44, 2, 21];
    assert_eq!(inflate_with_limit(&input, 5).unwrap(), b"hello");
    assert!(matches!(
        inflate_with_limit(&input, 4),
        Err(CompressError::OutputTooLarge { .. })
    ));
    let mut damaged = input;
    damaged[12] ^= 1;
    assert!(inflate(&damaged).is_err());
}
