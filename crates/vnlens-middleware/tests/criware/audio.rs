use super::*;
use vnlens_io::BinaryWriter;
#[test]
fn hca_header_checks_crc_and_counts_encoder_padding() -> Result<()> {
    let mut bytes = vec![0; 48];
    bytes[..4].copy_from_slice(b"HCA\0");
    BinaryWriter::u16_be(0x300, &mut bytes[4..]);
    BinaryWriter::u16_be(48, &mut bytes[6..]);
    bytes[8..12].copy_from_slice(b"fmt\0");
    BinaryWriter::u32_be(0x0200ac44, &mut bytes[12..]);
    BinaryWriter::u32_be(2, &mut bytes[16..]);
    BinaryWriter::u16_be(128, &mut bytes[20..]);
    BinaryWriter::u16_be(256, &mut bytes[22..]);
    bytes[24..28].copy_from_slice(b"comp");
    BinaryWriter::u16_be(100, &mut bytes[28..]);
    bytes[40..44].copy_from_slice(b"pad\0");
    let crc = crc16_8005(&bytes[..46]);
    BinaryWriter::u16_be(crc, &mut bytes[46..]);
    let h = HcaHeader::open(&bytes)?;
    assert_eq!(h.frames, 1664);
    assert_eq!(h.channels, 2);
    assert_eq!(h.sample_rate, 44100);
    bytes[12] ^= 1;
    assert!(HcaHeader::open(&bytes).is_err());
    Ok(())
}
