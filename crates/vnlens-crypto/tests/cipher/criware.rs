use super::*;
#[test]
fn utf_cipher_matches_known_magic_and_random_access() {
    let mut bytes = *b"@UTF";
    apply_utf(0, &mut bytes);
    assert_eq!(bytes, [0x1f, 0x9e, 0xf3, 0xf5]);
    let mut whole = vec![0; 1024];
    apply_utf(0, &mut whole);
    let mut range = vec![0; 19];
    apply_utf(997, &mut range);
    assert_eq!(&whole[997..1016], range);
    apply_utf(0, &mut bytes);
    assert_eq!(&bytes, b"@UTF");
}
