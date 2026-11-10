use super::*;
use vnlens_io::BinaryWriter;
#[allow(clippy::unwrap_used)]
fn ge() -> Vec<u8> {
    let mut decoded = vec![0; 8];
    BinaryWriter::u16_le(24, &mut decoded[2..]);
    BinaryWriter::u16_le(2, &mut decoded[4..]);
    BinaryWriter::u16_le(2, &mut decoded[6..]);
    decoded.extend([1, 2, 10, 20, 30, 1, 2, 3, 1, 1, 1, 2, 2, 2]);
    let mut bytes = vec![0; 40];
    bytes[..4].copy_from_slice(b"GE \0");
    BinaryWriter::u32_le(2, &mut bytes[12..]);
    BinaryWriter::u32_le(2, &mut bytes[16..]);
    BinaryWriter::u16_le(3, &mut bytes[28..]);
    BinaryWriter::u32_le(decoded.len() as u32, &mut bytes[32..]);
    BinaryWriter::u32_le(decoded.len() as u32 + 2, &mut bytes[36..]);
    bytes.extend([0, decoded.len() as u8]);
    bytes.extend(decoded);
    bytes
}
struct Base(Vec<u8>);
impl ResourceResolver for Base {
    fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
        Ok((name == "BASE.PGD").then(|| self.0.clone()))
    }
}
#[test]
fn predictors_and_xor_patch_preserve_base_canvas() -> Result<()> {
    let bytes = ge();
    let base = Pgd.decode(&bytes)?;
    let PixelBuffer::Bgra8(pixels) = base.pixels else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(
        pixels,
        [
            10, 20, 30, 255, 9, 18, 27, 255, 9, 19, 29, 255, 7, 16, 25, 255
        ]
    );
    let mut patch = vec![0; 56];
    patch[..4].copy_from_slice(b"PGD3");
    for at in [4, 6, 8, 10] {
        BinaryWriter::u16_le(1, &mut patch[at..]);
    }
    BinaryWriter::u16_le(24, &mut patch[12..]);
    patch[14..22].copy_from_slice(b"BASE.PGD");
    BinaryWriter::u32_le(4, &mut patch[48..]);
    BinaryWriter::u32_le(6, &mut patch[52..]);
    patch.extend([0, 4, 0, 1, 2, 3]);
    assert!(Pgd.decode(&patch).is_err());
    let image = Pgd.decode_with_resources(&patch, Some(&Base(bytes)))?;
    assert_eq!((image.meta.width, image.meta.height), (2, 2));
    let PixelBuffer::Bgra8(pixels) = image.pixels else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(&pixels[12..], [6, 18, 26, 255]);
    assert!(
        Pgd.decode_with_resources(&patch, Some(&Base(patch.clone())))
            .is_err()
    );
    Ok(())
}
#[test]
fn truncated_payload_and_invalid_predictors_fail() {
    let bytes = ge();
    for end in 0..bytes.len() {
        assert!(Pgd.decode(&bytes[..end]).is_err(), "length {end}");
    }
    assert!(predict(&[2, 1, 2, 3], 1, 1, 24).is_err());
}
