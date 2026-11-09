use super::*;
use nvlens_io::BinaryWriter;
#[test]
fn row_copy_and_run_codec_has_exact_pixel_output() -> Result<()> {
    // Each row: unsigned(0), copy previous row, unsigned(0) + one
    // repeated pixel. The initial predictor row is black.
    let mut bytes = vec![0; 46];
    BinaryWriter::u32_le(2, &mut bytes[16..]);
    bytes[20..24].copy_from_slice(&[4, 7, 7, 7]);
    BinaryWriter::u32_le(1, &mut bytes[30..]);
    bytes[42] = 0x12;
    let meta = ImageMeta {
        width: 2,
        height: 2,
        offset_x: -3,
        offset_y: 4,
        offset_unit: OffsetUnit::Pixels,
        bpp: 32,
    };
    let m = Meta {
        meta: meta.clone(),
        body: 0,
        schema: 3,
        name: "Cr6Ti".into(),
    };
    let image = decode(&bytes, &m)?;
    assert_eq!(image.meta, meta);
    let PixelBuffer::Rgba8(pixels) = image.pixels else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(pixels, [0, 0, 0, 255].repeat(4));
    assert!(
        matches!(decode(&bytes[..43],&m),Err(Error::Io(e)) if e.kind()==std::io::ErrorKind::UnexpectedEof)
    );
    Ok(())
}
