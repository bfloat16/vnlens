use super::*;
use nvlens_io::BinaryWriter;

#[test]
fn frame_access_is_lazy_and_preserves_alpha_and_bottom_up_rows() -> Result<()> {
    let mut bmp = vec![0; 62];
    bmp[..2].copy_from_slice(b"BM");
    BinaryWriter::u32_le(62, &mut bmp[2..]);
    BinaryWriter::u32_le(54, &mut bmp[10..]);
    BinaryWriter::u32_le(40, &mut bmp[14..]);
    BinaryWriter::u32_le(1, &mut bmp[18..]);
    BinaryWriter::u32_le(2, &mut bmp[22..]);
    BinaryWriter::u16_le(1, &mut bmp[26..]);
    BinaryWriter::u16_le(32, &mut bmp[28..]);
    bmp[54..].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let mut packed = Vec::new();
    for chunk in bmp.chunks(32) {
        packed.push((chunk.len() - 1) as u8);
        packed.extend_from_slice(chunk);
    }
    let mut data = vec![0; 18];
    BinaryWriter::u16_le(2, &mut data);
    BinaryWriter::u32_le(10, &mut data[2..]);
    BinaryWriter::u32_le(u32::MAX, &mut data[6..]);
    BinaryWriter::u32_le(bmp.len() as u32, &mut data[10..]);
    BinaryWriter::u32_le(packed.len() as u32, &mut data[14..]);
    data.extend(packed);
    assert_eq!(Mgr.frame_count(&data)?, 2);
    assert_eq!(Mgr.metadata(&data)?.ok_or(Error::InvalidFormat)?.height, 2);
    let image = Mgr.decode_frame(&data, 0)?;
    assert!(matches!(image.pixels, PixelBuffer::Bgra8(p) if p == [5,6,7,8,1,2,3,4]));
    assert!(Mgr.decode_frame(&data, 1).is_err());
    assert!(Mgr.decode_frame(&data, 2).is_err());
    assert!(Mgr.metadata(b"OggS unrelated resource")?.is_none());
    Ok(())
}
