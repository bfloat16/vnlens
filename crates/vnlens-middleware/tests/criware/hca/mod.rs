use super::*;
use vnlens_io::{BinaryWriter, BitWriter};

fn synthetic() -> Result<Vec<u8>> {
    let mut header = vec![0; 48];
    header[..4].copy_from_slice(b"HCA\0");
    BinaryWriter::u16_be(0x300, &mut header[4..]);
    BinaryWriter::u16_be(48, &mut header[6..]);
    header[8..12].copy_from_slice(b"fmt\0");
    BinaryWriter::u32_be(0x0100bb80, &mut header[12..]);
    BinaryWriter::u32_be(2, &mut header[16..]);
    header[24..28].copy_from_slice(b"comp");
    BinaryWriter::u16_be(32, &mut header[28..]);
    header[30..38].copy_from_slice(&[0, 15, 1, 0, 8, 4, 0, 2]);
    header[40..44].copy_from_slice(b"pad\0");
    let crc = crc16_8005(&header[..46]);
    BinaryWriter::u16_be(crc, &mut header[46..]);
    let mut bits = BitWriter::new(BitOrder::Msb);
    bits.write_bits(0xffff, 16)?;
    bits.write_bits(160, 9)?;
    bits.write_bits(0, 7)?;
    bits.write_bits(6, 3)?;
    bits.write_bits(60, 6)?;
    bits.write_bits(58, 6)?;
    bits.write_bits(35, 6)?;
    bits.write_bits(37, 6)?;
    bits.write_bits(45, 6)?;
    bits.write_bits(46, 6)?;
    // Resolutions 13/12 use ten/nine sign-magnitude bits. Two noise bands
    // and two HFR groups exercise HCA 3.0's reconstruction and PRNG state.
    for subframe in 0..8 {
        bits.write_bits(2 * (subframe + 1), 10)?;
        bits.write_bits(2 * (subframe + 2) + 1, 9)?;
    }
    let mut block = bits.into_bytes();
    block.resize(32, 0);
    let crc = crc16_8005(&block[..30]);
    BinaryWriter::u16_be(crc, &mut block[30..]);
    header.extend_from_slice(&block);
    header.extend(block);
    Ok(header)
}

fn synthetic_stereo(ms: u8) -> Result<Vec<u8>> {
    let mut header = synthetic()?[..48].to_vec();
    BinaryWriter::u32_be(0x0200bb80, &mut header[12..]);
    BinaryWriter::u16_be(192, &mut header[28..]);
    header[30..40].copy_from_slice(&[1, 15, 1, 0, 8, 4, 4, 0, ms, 0]);
    let crc = crc16_8005(&header[..46]);
    BinaryWriter::u16_be(crc, &mut header[46..]);
    let mut bits = BitWriter::new(BitOrder::Msb);
    bits.write_bits(0xffff, 16)?;
    bits.write_bits(0, 9)?;
    bits.write_bits(0, 7)?;
    for bands in [8, 4] {
        bits.write_bits(6, 3)?;
        for _ in 0..bands {
            bits.write_bits(63, 6)?;
        }
    }
    bits.write_bits(6, 4)?;
    bits.write_bits(0, 2)?;
    for _ in 0..7 {
        bits.write_bits(0, 1)?;
    }
    for subframe in 0..8 {
        for band in 0..8 {
            bits.write_bits(2 * (band + subframe + 1), 12)?;
        }
        for band in 0..4 {
            bits.write_bits(2 * (band + subframe + 2) + 1, 12)?;
        }
    }
    let mut block = bits.into_bytes();
    block.resize(192, 0);
    let crc = crc16_8005(&block[..190]);
    BinaryWriter::u16_be(crc, &mut block[190..]);
    header.extend_from_slice(&block);
    header.extend(block);
    Ok(header)
}

#[test]
fn v3_noise_hfr_and_overlap_match_native_sdk_golden() -> Result<()> {
    let bytes = synthetic()?;
    let mut decoder = Decoder::new(HcaHeader::open(&bytes)?)?;
    let mut samples = decoder.decode_frame(&bytes[48..80])?;
    samples.extend(decoder.decode_frame(&bytes[80..])?);
    // Generated from this unrestricted vector by the supplied static library's
    // HCADecoder_DecodeBlockFloat32, with no delay/padding cropping.
    for (index, bits) in [
        (0, 0x3602b00e),
        (1, 0x36be2b97),
        (2, 0x37336a40),
        (31, 0x3a0ef5e8),
        (63, 0x381a78a0),
        (64, 0xb81e1b10),
        (127, 0xbb38d202),
        (128, 0xbb352ab2),
        (255, 0xbb984769),
        (511, 0xbc07fbf7),
        (512, 0xbc05eb72),
        (895, 0xbc5e3863),
        (1023, 0xbc7befe5),
        (1024, 0xbc7825c6),
        (1025, 0xbc742705),
        (1151, 0xbb36a0af),
        (1152, 0xbb32032c),
        (1536, 0xbc03b5a3),
        (2047, 0xbc7fada5),
    ] {
        assert!((samples[index] - f32::from_bits(bits)).abs() < 0.00000001);
    }
    Ok(())
}

#[test]
fn v3_delta_intensity_and_mid_side_keep_independent_channels() -> Result<()> {
    for ms in [0, 1] {
        let bytes = synthetic_stereo(ms)?;
        let mut decoder = Decoder::new(HcaHeader::open(&bytes)?)?;
        let samples = decoder.decode_frame(&bytes[48..240])?;
        assert_eq!(samples.len(), 2048);
        assert!(
            samples
                .as_chunks::<2>()
                .0
                .iter()
                .any(|pair| (pair[0] - pair[1]).abs() > 0.001)
        );
    }
    Ok(())
}

#[test]
fn v3_noise_is_reproducible_and_bad_frames_fail_before_decoding() -> Result<()> {
    let bytes = synthetic()?;
    let header = HcaHeader::open(&bytes)?;
    let mut unknown = header.clone();
    unknown.version = 0x400;
    assert!(matches!(Decoder::new(unknown), Err(Error::Unsupported(_))));
    let mut first = Decoder::new(header.clone())?;
    let mut second = Decoder::new(header)?;
    let a = first.decode_frame(&bytes[48..80])?;
    let b = second.decode_frame(&bytes[48..80])?;
    assert_eq!(a, b);
    assert!(a.iter().any(|v| v.abs() > 0.00001));
    assert!(a.iter().all(|v| v.is_finite()));
    assert!(first.decode_frame(&bytes[48..79]).is_err());
    let mut corrupt = bytes[80..].to_vec();
    corrupt[10] ^= 1;
    assert!(matches!(
        first.decode_frame(&corrupt),
        Err(Error::Corrupt { offset: 80, .. })
    ));
    Ok(())
}
