use super::*;
use nvlens_io::BinaryWriter;
fn record(
    kind: u8,
    base: u32,
    dimensions: (u32, u32),
    flags: u32,
    alpha: &[u8],
    mask: &[u8],
    rgb: &[u8],
) -> Vec<u8> {
    let (width, height) = dimensions;
    let mut bytes = vec![kind];
    for value in [base, 0, width, height, flags, alpha.len() as u32] {
        let mut word = [0; 4];
        BinaryWriter::u32_le(value, &mut word);
        bytes.extend(word);
    }
    if flags & 4 != 0 {
        bytes.extend(alpha);
    }
    for part in [mask, rgb] {
        let mut word = [0; 4];
        BinaryWriter::u32_le(part.len() as u32, &mut word);
        bytes.extend(word);
        bytes.extend(part);
    }
    bytes
}
struct Base(Vec<u8>);
impl ResourceResolver for Base {
    fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
        Ok((name == "10000000.cimg").then(|| self.0.clone()))
    }
}
#[test]
fn raw_stride_alpha_and_encoded_base_patch() -> Result<()> {
    let bytes = record(
        b'a',
        10_000_000,
        (2, 1),
        6,
        &[128, 128, 128, 255, 255, 255, 0, 0],
        &[],
        &[10, 20, 30, 40, 50, 60, 0, 0],
    );
    let image = Csystem::Modern.decode(&bytes)?;
    let PixelBuffer::Bgra8(pixels) = &image.pixels else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(pixels, &[10, 20, 30, 128, 40, 50, 60, 255]);
    let png = image.to_png()?;
    let mut base = vec![b'c', 0, 0, 0, 0, 0];
    BinaryWriter::u32_be(png.len() as u32, &mut base[1..]);
    base.extend(png);
    let patch = record(b'd', 10_000_000, (999, 999), 7, &[64], &[2], &[1, 2, 3]);
    assert!(Csystem::Modern.decode(&patch).is_err());
    let image = Csystem::Modern.decode_with_resources(&patch, Some(&Base(base)))?;
    assert_eq!((image.meta.width, image.meta.height), (2, 1));
    let PixelBuffer::Bgra8(pixels) = &image.pixels else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(pixels, &[10, 20, 30, 128, 1, 2, 3, 64]);
    assert!(
        Csystem::Modern
            .decode_with_resources(&patch, Some(&Base(patch.clone())))
            .is_err()
    );
    for end in 0..bytes.len() {
        assert!(Csystem::Modern.decode(&bytes[..end]).is_err());
    }
    Ok(())
}
