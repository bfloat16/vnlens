#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn independent_custom_table_vector_and_empty_key() {
    let mut table = vec![0u8; TABLE_LEN];
    for (i, word) in table.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        BinaryWriter::u32_be(i as u32, word);
    }
    assert!(matches!(
        Blowfish::new(&table, &[]),
        Err(CipherError::EmptyKey)
    ));
    assert!(Blowfish::new(&table[..10], b"test").is_err());
    let cipher = Blowfish::new(&table, b"test").unwrap();
    let mut data = [0x37, 0x01, 0xba, 0x3b, 0xfe, 0x3e, 0x4d, 0xce, 0x55];
    cipher.decrypt(&mut data);
    assert_eq!(&data[..8], b"ABCDEFGH");
    assert_eq!(data[8], 0x55);
    assert_eq!(format!("{cipher:?}"), "Blowfish { .. }");
}
