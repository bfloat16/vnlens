#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn rejects_invalid_trailers_and_inconsistent_plaintext_length() {
    assert!(matches!(
        decrypt(b"short", b"key", &[]),
        Err(Error::InvalidFormat)
    ));
    let mut data = vec![0u8; 8 + TRAILER];
    let hash = md5::digest_parts(&[&data[..8], SALT]);
    data[8 + 0x20..].copy_from_slice(&hash);
    vnlens_io::BinaryWriter::u32_be(9, &mut data[8 + 0x10..8 + 0x14]);
    assert!(matches!(
        decrypt(&data, b"key", &[]),
        Err(Error::Corrupt { .. })
    ));
    data[0] ^= 1;
    assert!(matches!(
        decrypt(&data, b"key", &[]),
        Err(Error::InvalidFormat)
    ));
}
