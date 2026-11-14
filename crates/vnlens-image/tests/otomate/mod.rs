use super::*;

fn fixture(big: bool, fourcc: u32, block: &[u8]) -> Vec<u8> {
    let mut data = vec![0; 0x80 + block.len()];
    data[..4].copy_from_slice(if big { b"TID\x91" } else { b"TID\x90" });
    for (at, value) in [
        (0xc, 1),
        (0x10, 1),
        (0x14, 0x20),
        (0x44, 4),
        (0x48, 4),
        (0x4c, 32),
        (0x58, block.len() as u32),
        (0x5c, 0x80),
        (0x60, 4),
        (0x64, fourcc),
    ] {
        if big {
            BinaryWriter::u32_be(value, &mut data[at..]);
        } else {
            BinaryWriter::u32_le(value, &mut data[at..]);
        }
    }
    data[0x80..].copy_from_slice(block);
    data
}

#[test]
fn bc1_and_bc3_have_golden_pixels_in_both_header_byte_orders() -> Result<()> {
    let mut bc1 = [0; 8];
    BinaryWriter::u16_le(0xf800, &mut bc1);
    for big in [false, true] {
        let image = crate::decode_as("tid/otomate", &fixture(big, 0x3154_5844, &bc1))?;
        assert_eq!((image.meta.width, image.meta.height), (4, 4));
        let PixelBuffer::Bgra8(pixels) = image.pixels else {
            return Err(Error::InvalidFormat);
        };
        assert_eq!(pixels, [0, 0, 255, 255].repeat(16));
        let mut bc3 = [0; 16];
        bc3[0] = 128;
        BinaryWriter::u16_le(0x07e0, &mut bc3[8..]);
        let image = crate::decode_as("tid/otomate", &fixture(big, 0x3554_5844, &bc3))?;
        let PixelBuffer::Bgra8(pixels) = image.pixels else {
            return Err(Error::InvalidFormat);
        };
        assert_eq!(pixels, [0, 255, 0, 128].repeat(16));
    }
    Ok(())
}

#[test]
fn bc1_transparency_and_truncated_surfaces_are_not_silently_accepted() -> Result<()> {
    let mut block = [0; 8];
    BinaryWriter::u32_le(u32::MAX, &mut block[4..]);
    let data = fixture(false, 0x3154_5844, &block);
    let image = Tid.decode(&data)?;
    let PixelBuffer::Bgra8(pixels) = image.pixels else {
        return Err(Error::InvalidFormat);
    };
    assert!(pixels.as_chunks::<4>().0.iter().all(|pixel| pixel[3] == 0));
    assert!(Tid.decode(&data[..data.len() - 1]).is_err());
    assert!(Tid.decode_frame(&data, 1).is_err());
    Ok(())
}
