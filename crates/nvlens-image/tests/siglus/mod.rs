use super::*;
use nvlens_io::BinaryWriter;
fn literals(bytes: &[u8]) -> Vec<u8> {
    let mut data = vec![0; 8];
    for chunk in bytes.chunks(8) {
        data.push(0xff);
        data.extend(chunk);
    }
    let packed = data.len() as u32;
    BinaryWriter::u32_le(packed, &mut data);
    BinaryWriter::u32_le(bytes.len() as u32, &mut data[4..]);
    data
}
#[test]
fn frame_selection_is_independent_and_keeps_transparency() -> Result<()> {
    let mut data = vec![0; 9 + 48];
    data[0] = 2;
    BinaryWriter::u16_le(2, &mut data[1..]);
    BinaryWriter::u16_le(1, &mut data[3..]);
    BinaryWriter::u32_le(2, &mut data[5..]);
    let mut decoded = vec![0; 20];
    BinaryWriter::u32_le(2, &mut decoded);
    for (frame, color) in [[10, 20, 30, 255], [40, 50, 60, 128]]
        .into_iter()
        .enumerate()
    {
        let start = decoded.len();
        decoded.resize(start + 116 + 92 + 4, 0);
        BinaryWriter::u32_le(start as u32, &mut decoded[4 + frame * 8..]);
        BinaryWriter::u32_le(212, &mut decoded[8 + frame * 8..]);
        BinaryWriter::u16_le(1, &mut decoded[start..]);
        BinaryWriter::u16_le(1, &mut decoded[start + 2..]);
        BinaryWriter::u16_le(frame as u16, &mut decoded[start + 116..]);
        BinaryWriter::u16_le(1, &mut decoded[start + 122..]);
        BinaryWriter::u16_le(1, &mut decoded[start + 124..]);
        decoded[start + 208..start + 212].copy_from_slice(&color);
    }
    data.extend(literals(&decoded));
    assert_eq!(G00.frame_count(&data)?, 2);
    for (frame, expected) in [
        (0, vec![10, 20, 30, 255, 0, 0, 0, 0]),
        (1, vec![0, 0, 0, 0, 40, 50, 60, 128]),
    ] {
        let image = G00.decode_frame(&data, frame)?;
        assert!(matches!(image.pixels,PixelBuffer::Bgra8(ref p) if p==&expected));
    }
    assert!(G00.decode_frame(&data, 2).is_err());
    assert!(G00.decode_frame(&data[..data.len() - 1], 0).is_err());
    // Corrupt the unselected frame. Frame zero stays independently usable.
    decoded[232] = 9;
    data.truncate(57);
    data.extend(literals(&decoded));
    assert!(G00.decode_frame(&data, 0).is_ok());
    assert!(G00.decode_frame(&data, 1).is_err());
    Ok(())
}
#[test]
fn siglus_bgr_literals_expand_before_back_references() -> Result<()> {
    let mut data = vec![0; 13];
    BinaryWriter::u16_le(2, &mut data[1..]);
    BinaryWriter::u16_le(1, &mut data[3..]);
    BinaryWriter::u32_le(14, &mut data[5..]);
    BinaryWriter::u32_le(8, &mut data[9..]);
    data.extend([1, 10, 20, 30, 0x10, 0]);
    assert!(
        matches!(G00.decode(&data)?.pixels,PixelBuffer::Bgra8(ref p) if p==&[10,20,30,255,10,20,30,255])
    );
    Ok(())
}
