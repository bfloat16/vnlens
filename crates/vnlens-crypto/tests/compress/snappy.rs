use super::*;

#[test]
fn literals_copy_tags_and_overlapping_history() {
    for stream in [
        vec![9, 8, b'a', b'b', b'c', 9, 3],
        vec![9, 8, b'a', b'b', b'c', 22, 3, 0],
        vec![9, 8, b'a', b'b', b'c', 23, 3, 0, 0, 0],
    ] {
        assert!(validate(&stream, 9).is_ok());
        assert_eq!(
            decode(&stream, 9).ok().as_deref(),
            Some(b"abcabcabc".as_slice())
        );
        for end in 0..stream.len() {
            assert!(decode(&stream[..end], 9).is_err());
            assert!(validate(&stream[..end], 9).is_err());
        }
    }
    assert_eq!(decode(&[0], 0).ok(), Some(Vec::new()));
    assert_eq!(
        decode(&[4, 240, 3, b't', b'e', b's', b't'], 4)
            .ok()
            .as_deref(),
        Some(b"test".as_slice())
    );
    for (stream, size) in [
        (&[1, 1, 0][..], 1),
        (&[1, 1, 1], 1),
        (&[0, 0, 0], 0),
        (&[0xff, 0xff, 0xff, 0xff, 0x10], 0),
        (&[1, 0, b'a'], 2),
    ] {
        assert!(decode(stream, size).is_err());
    }
}
