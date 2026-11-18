use super::*;
fn fixture() -> Vec<u8> {
    let mut bytes = vec![0; 164];
    bytes[..4].copy_from_slice(b"DDS ");
    for (at, value) in [
        (4, 124),
        (12, 4),
        (16, 4),
        (76, 32),
        (128, 98),
        (132, 3),
        (140, 1),
    ] {
        BinaryWriter::u32_le(value, &mut bytes[at..]);
    }
    bytes[84..88].copy_from_slice(b"DX10");
    bytes[148] = 0x40;
    bytes
}
#[test]
fn bc7_mode_six_black_and_exact_surface_bounds() -> Result<()> {
    let mut bytes = fixture();
    let image = Dds.decode(&bytes)?;
    assert_eq!((image.meta.width, image.meta.height), (4, 4));
    assert!(matches!(image.pixels,PixelBuffer::Bgra8(pixels) if pixels==[0;64]));
    for end in [4, 127, 147, 148, 163] {
        assert!(Dds.decode(&bytes[..end]).is_err());
    }
    bytes[148] = 0;
    assert!(Dds.decode(&bytes).is_err());
    Ok(())
}

fn legacy(fourcc: &[u8; 4], width: u32, height: u32, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0; 128];
    data[..4].copy_from_slice(b"DDS ");
    for (at, value) in [(4, 124), (12, height), (16, width), (76, 32)] {
        BinaryWriter::u32_le(value, &mut data[at..]);
    }
    data[84..88].copy_from_slice(fourcc);
    data.extend_from_slice(payload);
    data
}

#[test]
fn bc1_bc3_pixels_mip_chain_and_odd_dimensions() -> Result<()> {
    let red = [0, 0xf8, 0, 0, 0, 0, 0, 0];
    let data = legacy(b"DXT1", 3, 2, &red);
    assert!(
        matches!(Dds.decode(&data)?.pixels,PixelBuffer::Bgra8(p) if p == [0,0,255,255].repeat(6))
    );
    let mut block = vec![255, 0, 0, 0, 0, 0, 0, 0];
    block.extend_from_slice(&red);
    let data = legacy(b"DXT5", 4, 4, &block);
    assert!(
        matches!(Dds.decode(&data)?.pixels,PixelBuffer::Bgra8(p) if p == [0,0,255,255].repeat(16))
    );
    let mut data = legacy(b"DXT1", 4, 4, &red.repeat(3));
    BinaryWriter::u32_le(3, &mut data[28..]);
    assert_eq!(Dds.frame_count(&data)?, 3);
    assert_eq!(Dds.decode_frame(&data, 2)?.meta.width, 1);
    BinaryWriter::u32_le(4, &mut data[28..]);
    assert!(Dds.decode(&data).is_err());
    Ok(())
}

#[test]
fn rgba_volume_slices_pitch_and_bgra_masks() -> Result<()> {
    let mut data = legacy(
        &[0; 4],
        1,
        1,
        &[1, 2, 3, 4, 0, 0, 0, 0, 5, 6, 7, 8, 0, 0, 0, 0],
    );
    for (at, value) in [
        (8, 8),
        (20, 8),
        (24, 2),
        (88, 32),
        (92, 0xff),
        (96, 0xff00),
        (100, 0xff0000),
        (104, 0xff000000),
        (112, 0x20_0000),
    ] {
        BinaryWriter::u32_le(value, &mut data[at..]);
    }
    assert_eq!(Dds.frame_count(&data)?, 2);
    assert!(matches!(Dds.decode_frame(&data,1)?.pixels,PixelBuffer::Rgba8(p) if p==[5,6,7,8]));
    BinaryWriter::u32_le(0xff0000, &mut data[92..]);
    BinaryWriter::u32_le(0xff, &mut data[100..]);
    assert!(matches!(Dds.decode(&data)?.pixels,PixelBuffer::Rgba8(p) if p==[3,2,1,4]));
    Ok(())
}

#[test]
fn dx10_cube_arrays_include_every_face_and_reject_short_storage() -> Result<()> {
    let mut data = fixture();
    BinaryWriter::u32_le(4, &mut data[136..]);
    BinaryWriter::u32_le(2, &mut data[140..]);
    let block = data[148..].to_vec();
    data.truncate(148);
    data.extend_from_slice(&block.repeat(12));
    assert_eq!(Dds.frame_count(&data)?, 12);
    assert_eq!(Dds.decode_frame(&data, 11)?.meta.height, 4);
    data.pop();
    assert!(Dds.decode_frame(&data, 0).is_err());
    Ok(())
}
