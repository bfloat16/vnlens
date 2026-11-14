use super::*;
use vnlens_io::BinaryWriter;
#[test]
fn reverse_literals_prefix_and_truncation_are_checked() {
    let mut bytes = vec![0; 16];
    bytes[..8].copy_from_slice(b"CRILAYLA");
    BinaryWriter::u32_le(3, &mut bytes[8..]);
    BinaryWriter::u32_le(4, &mut bytes[12..]);
    bytes.extend([0x20, 0x8c, 0x98, 0x31]);
    bytes.extend([0x55; 256]);
    let decoded = decompress(&bytes, 259);
    assert!(decoded.is_ok());
    if let Ok(decoded) = decoded {
        assert_eq!(&decoded[..256], &[0x55; 256]);
        assert_eq!(&decoded[256..], b"abc");
    }
    assert!(decompress(&bytes[..bytes.len() - 1], 259).is_err());
    assert!(decompress(&bytes, 260).is_err());
    bytes[..8].fill(0);
    assert!(decompress(&bytes, 259).is_ok());
}
