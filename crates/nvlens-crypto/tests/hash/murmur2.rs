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
    assert_eq!(hash(&(0..32).collect::<Vec<u8>>(), 0), 0xf1bc_6c23);
}
