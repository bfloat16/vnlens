use super::*;

#[test]
fn sha1_nist_vectors() {
    for (input, expected) in [
        ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        ),
    ] {
        let mut hash = sha1::Sha1::new();
        for part in input.as_bytes().chunks(7) {
            hash.update(part);
        }
        assert_eq!(hash.digest().to_string(), expected);
    }
}
