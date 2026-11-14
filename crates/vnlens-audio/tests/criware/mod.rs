use super::*;
use vnlens_crypto::checksum::crc16::crc16_8005;
use vnlens_io::BinaryWriter;

fn hca_fixture(cipher: u16, corrupt_block: bool) -> Vec<u8> {
    let mut bytes = vec![0; 54 + 16];
    bytes[..4].copy_from_slice(b"HCA\0");
    BinaryWriter::u16_be(0x300, &mut bytes[4..]);
    BinaryWriter::u16_be(54, &mut bytes[6..]);
    bytes[8..12].copy_from_slice(b"fmt\0");
    BinaryWriter::u32_be(0x0100ac44, &mut bytes[12..]);
    BinaryWriter::u32_be(1, &mut bytes[16..]);
    BinaryWriter::u16_be(0, &mut bytes[20..]);
    BinaryWriter::u16_be(0, &mut bytes[22..]);
    bytes[24..28].copy_from_slice(b"comp");
    BinaryWriter::u16_be(16, &mut bytes[28..]);
    bytes[30..38].copy_from_slice(&[0, 15, 1, 0, 1, 1, 0, 0]);
    bytes[40..44].copy_from_slice(b"ciph");
    BinaryWriter::u16_be(cipher, &mut bytes[44..]);
    bytes[46..50].copy_from_slice(b"pad\0");
    BinaryWriter::u16_be(crc16_8005(&bytes[..52]), &mut bytes[52..]);
    if corrupt_block {
        bytes[54] = 1;
    } else {
        BinaryWriter::u16_be(crc16_8005(&bytes[54..68]), &mut bytes[68..]);
    }
    bytes
}

#[test]
fn hca_metadata_checks_cipher_block_crc_and_cancellation() -> Result<()> {
    let encrypted = hca_fixture(56, false);
    let meta = crate::metadata_as("cri/hca", &encrypted)?.ok_or(Error::InvalidFormat)?;
    assert_eq!(meta.codec, "HCA");
    assert_eq!(meta.channels, 1);
    assert_eq!(meta.sample_rate, 44100);
    assert_eq!(meta.frames, Some(1024));
    assert!(matches!(
        crate::decode_cancellable_as("cri/hca", &encrypted, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    assert!(matches!(
        crate::decode_as("cri/hca", &encrypted),
        Err(Error::UnknownScheme(Some(_)))
    ));
    let bad_crc = hca_fixture(0, true);
    assert!(matches!(
        crate::decode_as("cri/hca", &bad_crc),
        Err(Error::Corrupt { offset: 54, .. })
    ));
    Ok(())
}

#[test]
fn adx_silence_decodes_with_native_frame_count_and_cancellation() -> Result<()> {
    let mut bytes = vec![0; 36 + 18];
    bytes[..2].copy_from_slice(&[0x80, 0]);
    BinaryWriter::u16_be(32, &mut bytes[2..]);
    bytes[4..8].copy_from_slice(&[3, 18, 4, 1]);
    BinaryWriter::u32_be(22050, &mut bytes[8..]);
    BinaryWriter::u32_be(32, &mut bytes[12..]);
    BinaryWriter::u16_be(500, &mut bytes[16..]);
    bytes[18] = 3;
    bytes[30..36].copy_from_slice(b"(c)CRI");
    let pcm = Adx.decode(&bytes)?;
    assert_eq!(pcm.meta.frames, Some(32));
    assert_eq!(pcm.samples.len(), 32);
    assert!(pcm.samples.iter().all(|&v| v == 0.0));
    assert!(matches!(
        crate::decode_cancellable_as("cri/adx", &bytes, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    Ok(())
}
