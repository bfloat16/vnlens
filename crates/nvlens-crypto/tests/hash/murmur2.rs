use super::*;

#[test]
fn independent_vectors() {
    for (input, expected) in [
        (&b""[..], 0),
        (b"a", 0x9268_5f5e),
        (b"abc", 0x1357_7c9b),
        (b"abcd", 0x2687_3021),
        (b"hello", 0xe561_29cb),
    ] {
        assert_eq!(hash(input, 0), expected);
    }
    let bytes: Vec<u8> = (0..32).collect();
    assert_eq!(hash(&bytes, 0), 0xf1bc_6c23);
    for step in 1..=7 {
        let mut streaming = Murmur2::new(bytes.len() as u64, 0);
        for chunk in bytes.chunks(step) {
            streaming.update(chunk);
        }
        assert_eq!(streaming.finish(), 0xf1bc_6c23);
    }
}
