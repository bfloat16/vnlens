use super::*;
use crate::{decode_as, metadata_as};
use nvlens_io::BinaryWriter;

fn sample_tga(offset_x: u16, offset_y: u16) -> Vec<u8> {
    let mut data = vec![0u8; 26];
    data[2] = 2; // Uncompressed true-color
    BinaryWriter::u16_le(offset_x, &mut data[8..10]);
    BinaryWriter::u16_le(offset_y, &mut data[10..12]);
    BinaryWriter::u16_le(2, &mut data[12..14]); // Width
    BinaryWriter::u16_le(1, &mut data[14..16]); // Height
    data[16] = 32; // 32 bpp
    data[17] = 0x28; // Top-left origin + 8 alpha bits
    data[18..26].copy_from_slice(&[30, 20, 10, 255, 60, 50, 40, 128]); // BGRA pixels
    data
}

#[test]
fn decodes_tga_pixels_and_preserves_header_offsets() -> Result<()> {
    let data = sample_tga(12, 34);
    let meta = metadata_as("tga", &data)?.ok_or(Error::InvalidFormat)?;
    assert_eq!(meta.width, 2);
    assert_eq!(meta.height, 1);
    assert_eq!(meta.offset_x, 12);
    assert_eq!(meta.offset_y, 34);
    assert_eq!(meta.offset_unit, OffsetUnit::Pixels);
    assert_eq!(meta.bpp, 32);

    let image = decode_as("tga", &data)?;
    assert_eq!(image.meta, meta);
    assert!(matches!(
        image.pixels,
        PixelBuffer::Rgba8(ref pixels) if pixels == &[10, 20, 30, 255, 40, 50, 60, 128]
    ));
    Ok(())
}

#[test]
fn rejects_truncated_or_invalid_tga() {
    let data = sample_tga(0, 0);
    assert!(decode_as("tga", &data[..10]).is_err());
    assert!(decode_as("tga", &data[..data.len() - 1]).is_err());
}
