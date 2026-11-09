#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn matches_independent_crc_md5_vector_and_wraps_offsets() {
    let stream = Keystream::new(&[0; KEYSTREAM_LEN], b"test").unwrap();
    let mut first = [0; 16];
    stream.descramble(&mut first, 0);
    assert_eq!(
        first,
        [
            0x6f, 0xaf, 0xad, 0xf0, 0x17, 0xb4, 0xf3, 0x8e, 0x08, 0x95, 0xae, 0xfb, 0x4a, 0x4b,
            0xa8, 0x09
        ]
    );
    let mut wrap = [0; 17];
    stream.descramble(&mut wrap, usize::MAX);
    assert_eq!(&wrap[1..], &first);
    assert!(!format!("{stream:?}").contains("111"));
}
