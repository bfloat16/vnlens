use super::*;
use vnlens_io::BinaryWriter;

#[test]
fn image_name_records_include_their_numeric_field() -> Result<()> {
    let name = b"Cr6Tix";
    let mut bytes = vec![0; 14];
    BinaryWriter::u32_le(0x29f6cba4, &mut bytes);
    BinaryWriter::u16_le(20, &mut bytes[4..]);
    BinaryWriter::u16_le(1, &mut bytes[6..]);
    BinaryWriter::u16_le(0xffff, &mut bytes[8..]);
    BinaryWriter::u16_le(3, &mut bytes[10..]);
    BinaryWriter::u16_le(name.len() as u16, &mut bytes[12..]);
    bytes.extend(name);
    bytes.extend([
        1, 2, 0, 1, b'A', 0x34, 0x12, 0, 0, 1, b'B', 0x78, 0x56, 0, 0,
    ]);
    let at = bytes.len();
    bytes.resize(at + 46, 0);
    for offset in [4, 6, 12, 14] {
        BinaryWriter::u16_le(2, &mut bytes[at + offset..]);
    }
    BinaryWriter::u32_le(2, &mut bytes[at + 16..]);
    bytes[at + 20..at + 24].copy_from_slice(&[4, 7, 7, 7]);
    BinaryWriter::u32_le(1, &mut bytes[at + 30..]);
    bytes[at + 42] = 0x12;
    let image = Rugp.decode(&bytes)?;
    assert_eq!((image.meta.width, image.meta.height), (2, 2));
    let PixelBuffer::Rgba8(pixels) = image.pixels else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(pixels, [0, 0, 0, 255].repeat(4));
    assert!(Rugp.decode(&bytes[..at - 1]).is_err());
    Ok(())
}
