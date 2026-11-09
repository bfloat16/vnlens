use super::*;
use nvlens_io::BinaryWriter;

fn transport(width: u16, height: u16, frames: &[(u8, u16, &[u8])]) -> Vec<u8> {
    let mut data = MAGIC.to_vec();
    data.resize(16, 0);
    BinaryWriter::u16_le(width, &mut data[8..]);
    BinaryWriter::u16_le(height, &mut data[10..]);
    BinaryWriter::u32_le(frames.len() as u32, &mut data[12..]);
    for &(mode, flags, encoded) in frames {
        let at = data.len();
        data.resize(at + 9, 0);
        data[at] = mode;
        BinaryWriter::u16_le(flags, &mut data[at + 1..]);
        BinaryWriter::u16_le(8, &mut data[at + 3..]);
        BinaryWriter::u32_le(encoded.len() as u32, &mut data[at + 5..]);
        data.extend_from_slice(encoded);
    }
    data
}

#[test]
fn key_and_delta_frames_match_independent_pixel_vectors() -> Result<()> {
    // Synthetic bitstreams checked against rvmm's scalar/MMX routines in
    // an isolated CPU emulator. These contain no game pixels or payloads.
    let yuv_key = &[0x74, 0x69, 0x27, 0x03];
    let yuv_delta = &[0x54, 0x65, 0x91, 0x01];
    let cases = [
        (
            transport(4, 4, &[(1, 0x575, yuv_key)]),
            [104, 81, 73, 255],
            16,
        ),
        (
            transport(4, 4, &[(1, 0x575, yuv_key), (0, 0x575, yuv_delta)]),
            [28, 17, 23, 255],
            16,
        ),
        (
            transport(2, 2, &[(1, 0x1b6, &[0x54, 0xa5, 0x1d, 0x02])]),
            [28, 32, 38, 255],
            4,
        ),
    ];
    for (data, expected, count) in cases {
        let image = crate::decode(&data)?.ok_or(Error::InvalidFormat)?;
        let PixelBuffer::Rgba8(pixels) = &image.pixels else {
            return Err(Error::InvalidFormat);
        };
        assert_eq!(*pixels, expected.repeat(count));
        assert_eq!(crate::frame_count(&data)?, Some(1));
        assert!(image.to_png()?.starts_with(b"\x89PNG\r\n\x1a\n"));
        for end in MAGIC.len()..data.len() {
            assert!(Frame.decode(&data[..end]).is_err());
        }
    }
    Ok(())
}

#[test]
fn frame_boundaries_and_dependency_order_are_checked() -> Result<()> {
    assert!(
        Frame
            .decode(&transport(2, 2, &[(0, 0x575, &[0x74])]))
            .is_err()
    );
    assert!(Frame.decode(&transport(2, 2, &[])).is_err());
    assert!(Frame.decode(&transport(0, 2, &[(1, 0x575, &[])])).is_err());
    // unsigned(1) requests two 2x2 blocks in a one-block row.
    assert!(Frame.decode(&transport(2, 2, &[(1, 0x575, &[1])])).is_err());
    assert!(matches!(
        Frame.decode(&transport(2, 2, &[(1, 0x775, &[0])])),
        Err(Error::Unsupported(_))
    ));
    let mut data = transport(4, 4, &[(1, 0x575, &[0x74, 0x69, 0x27, 0x03])]);
    data.push(0);
    assert!(Frame.decode(&data).is_err());
    // The last partial block writes only actual image pixels.
    let image = Frame.decode(&transport(3, 3, &[(1, 0x575, &[0x74, 0x69, 0x27, 0x03])]))?;
    assert_eq!(image.meta.rgba_size()?, 36);
    Ok(())
}
