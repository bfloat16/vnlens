use super::*;
use nvlens_io::BinaryWriter;

#[test]
fn frames_keep_declared_order_and_validate_payload_bounds() -> Result<()> {
    let mut data = vec![0; 53];
    BinaryWriter::u16_le(2, &mut data[21..]);
    BinaryWriter::u32_le(2, &mut data[24..]);
    BinaryWriter::u32_le(2, &mut data[32..]);
    BinaryWriter::u32_le(0, &mut data[37..]);
    BinaryWriter::u32_le(2, &mut data[45..]);
    let frames: Vec<_> = animation_index(&data)?
        .frames
        .into_iter()
        .map(|f| f.span)
        .collect();
    assert_eq!(frames, vec![span(51, 2), span(49, 2)]);
    assert!(animation_index(&data[..52]).is_err());
    assert!(animation_index(&data[..35]).is_err());
    Ok(())
}
