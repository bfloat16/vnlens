use super::*;
use nvlens_io::BinaryWriter;

#[test]
fn opaque_v2_has_no_alpha_slot_and_handles_partial_blocks() -> Result<()> {
    let mut bytes = vec![0; 16 + 176];
    bytes[0] = 1;
    bytes[16] = 1;
    let offset = bytes.len() + 4;
    let mut word = [0; 4];
    BinaryWriter::u32_le(offset as u32, &mut word);
    bytes.extend(word);
    // One present color block: 192 coefficients, three zero DC and AC codes.
    bytes.extend([1, 0xc0, 1, 0, 0]);
    let meta = ImageMeta {
        width: 3,
        height: 5,
        bpp: 24,
        offset_x: 0,
        offset_y: 0,
        offset_unit: crate::OffsetUnit::Pixels,
    };
    let image = decode(meta, &[1; 128], &bytes)?;
    let PixelBuffer::Rgba8(pixels) = image.pixels else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(pixels.len(), 3 * 5 * 4);
    assert!(
        pixels
            .as_chunks::<4>()
            .0
            .iter()
            .all(|pixel| *pixel == [128, 128, 128, 255])
    );
    Ok(())
}
#[test]
fn alpha_uses_padded_storage_and_crops_to_visible_pixels() -> Result<()> {
    let mut data = vec![0; 4];
    BinaryWriter::u32_le(1, &mut data);
    for row in 0..8 {
        data.push(0);
        data.extend((0..8).map(|column| (row * 8 + column) as u8));
    }
    let mut pixels = vec![0; 3 * 5 * 4];
    alpha(&data, &mut pixels, 3, 5)?;
    for y in 0..5 {
        for x in 0..3 {
            assert_eq!(pixels[(y * 3 + x) * 4 + 3], (y * 8 + x) as u8);
        }
    }
    data[4] = 1;
    assert!(alpha(&data, &mut pixels, 3, 5).is_err());
    Ok(())
}
