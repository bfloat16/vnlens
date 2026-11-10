use super::*;
use nvlens_io::BinaryWriter;

fn picture(base: u32, width: u32, height: u32, flags: u32, mask: &[u8], rgb: &[u8]) -> Vec<u8> {
    let mut fields = [0; 20];
    fields[0] = base;
    fields[3] = width;
    fields[8] = height;
    fields[11] = rgb.len() as u32;
    fields[13] = flags;
    fields[17] = mask.len() as u32;
    let mut bytes = vec![b'a', 0xef];
    for value in fields {
        let low = value % 233;
        let high = value / 233;
        bytes.push(if low == 0 { 0xfb } else { low as u8 });
        bytes.extend(std::iter::repeat_n(0xe9, (high / 233) as usize));
        bytes.push(if high % 233 == 0 {
            0xfb
        } else {
            (high % 233) as u8
        });
        bytes.push(0xef);
    }
    bytes.extend(mask);
    bytes.extend(rgb);
    bytes
}

struct Pictures(Vec<u8>);
impl ResourceResolver for Pictures {
    fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
        Ok((name == "picture/3.b0").then(|| self.0.clone()))
    }
}

#[test]
fn legacy_numbers_dib_rows_and_ordinal_patch_match_pixels() -> Result<()> {
    let bytes = picture(233 * 233 + 7, 1, 2, 0, &[], &[1, 2, 3, 0, 4, 5, 6, 0]);
    let p = planes(&bytes)?;
    assert_eq!(p.base, 233 * 233 + 7);
    let image = Csystem::Legacy.decode(&bytes)?;
    let PixelBuffer::Bgra8(pixels) = &image.pixels else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(pixels, &[4, 5, 6, 255, 1, 2, 3, 255]);
    let patch = picture(3, 1, 2, 1, &[1], &[7, 8, 9]);
    let image = Csystem::Legacy.decode_with_resources(&patch, Some(&Pictures(bytes.clone())))?;
    let PixelBuffer::Bgra8(pixels) = image.pixels else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(pixels, &[4, 5, 6, 255, 7, 8, 9, 255]);
    assert!(
        Csystem::Legacy
            .decode_with_resources(&patch, Some(&Pictures(patch.clone())))
            .is_err()
    );
    for end in 0..bytes.len() {
        assert!(Csystem::Legacy.decode(&bytes[..end]).is_err());
    }
    Ok(())
}

#[test]
fn legacy_png_envelope_starts_at_five_and_preserves_orientation() -> Result<()> {
    let image = Csystem::Legacy.decode(&picture(0, 1, 2, 0, &[], &[1, 2, 3, 0, 4, 5, 6, 0]))?;
    let png = image.to_png()?;
    let mut bytes = vec![b'c', 0, 0, 0, 0];
    BinaryWriter::u32_be(png.len() as u32, &mut bytes[1..]);
    bytes.extend(png);
    assert_eq!(Csystem::Legacy.decode(&bytes)?.to_png()?, image.to_png()?);
    assert!(Csystem::Modern.decode(&bytes).is_err());
    Ok(())
}
