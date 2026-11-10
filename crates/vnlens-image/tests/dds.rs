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
