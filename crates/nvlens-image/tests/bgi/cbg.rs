use super::*;
use nvlens_io::BinaryWriter;

#[test]
fn v1_checksum_huffman_runs_and_predictor() -> Result<()> {
    let mut header = vec![0; 48];
    header[..16].copy_from_slice(b"CompressedBG___\0");
    BinaryWriter::u16_le(2, &mut header[16..]);
    BinaryWriter::u16_le(2, &mut header[18..]);
    BinaryWriter::u16_le(24, &mut header[20..]);
    BinaryWriter::u32_le(13, &mut header[32..]);
    BinaryWriter::u32_le(256, &mut header[40..]);
    BinaryWriter::u16_le(1, &mut header[46..]);
    let mut generator = Generator::new(0);
    for _ in 0..256 {
        header.push(1u8.wrapping_add(generator.next_byte()));
    }
    header.extend([12, 10, 10, 10, 20, 20, 20, 30, 30, 30, 40, 40, 40]);
    let image = decode(&header)?;
    let PixelBuffer::Rgba8(pixels) = image.pixels else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(
        pixels,
        [
            10, 10, 10, 255, 30, 30, 30, 255, 40, 40, 40, 255, 75, 75, 75, 255
        ]
    );
    let mut broken = header.clone();
    broken[48] ^= 1;
    assert!(decode(&broken).is_err());
    for length in [16, 47, 48, 303, 304, header.len() - 1] {
        assert!(decode(&header[..length]).is_err());
    }
    Ok(())
}
