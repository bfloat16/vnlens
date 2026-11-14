#![allow(clippy::unwrap_used)]

use super::*;
use vnlens_io::BinaryWriter;
fn fixture(signature: &[u8]) -> Vec<u8> {
    let image = Image {
        meta: ImageMeta {
            width: 1,
            height: 1,
            offset_x: 0,
            offset_y: 0,
            offset_unit: OffsetUnit::Pixels,
            bpp: 32,
        },
        pixels: PixelBuffer::Rgba8(vec![30, 20, 10, 128]),
    };
    let png = image.to_png().unwrap();
    let mut data = vec![0; 140];
    data[..4].copy_from_slice(signature);
    BinaryWriter::u32_le(3, &mut data[16..]);
    BinaryWriter::u32_le(1, &mut data[20..]);
    for start in [60, 100] {
        BinaryWriter::u32_le((-4i32) as u32, &mut data[start + 8..]);
        BinaryWriter::u32_le(7, &mut data[start + 12..]);
        BinaryWriter::u32_le(1, &mut data[start + 16..]);
        BinaryWriter::u32_le(1, &mut data[start + 20..]);
        BinaryWriter::u32_le(png.len() as u32, &mut data[start + 36..]);
    }
    data.extend_from_slice(&png);
    data.extend(png);
    data
}
#[test]
fn skips_group_records_preserves_offsets_and_unpremultiplies_selected_layer() {
    let bytes = fixture(b"PNAP");
    assert_eq!(Pna.frame_count(&bytes).unwrap(), 2);
    let image = Pna.decode_frame(&bytes, 1).unwrap();
    assert_eq!((image.meta.offset_x, image.meta.offset_y), (-4, 7));
    assert!(matches!(&image.pixels, PixelBuffer::Rgba8(p) if p == &[59,39,19,128]));
    assert_eq!(
        crate::metadata_as("image/standard", &image.to_png().unwrap())
            .unwrap()
            .unwrap(),
        image.meta
    );
    assert!(Pna.decode_frame(&bytes, 2).is_err());
    assert!(Pna.frame_count(&bytes[..bytes.len() - 1]).is_err());
    let straight = Pna.decode(&fixture(b"PNAS")).unwrap();
    assert!(matches!(straight.pixels, PixelBuffer::Rgba8(p) if p == [30,20,10,128]));
}

#[test]
fn ordinary_png_mos_uses_the_registered_will_reader() -> Result<()> {
    let container = fixture(b"PNAS");
    let (_, png) = layer(&container, 0)?;
    assert_eq!(Pna.frame_count(png)?, 1);
    let image = Pna.decode(png)?;
    assert_eq!(Pna.metadata(png)?, Some(image.meta));
    assert!(matches!(image.pixels, PixelBuffer::Rgba8(p) if p == [30, 20, 10, 128]));
    assert!(Pna.decode_frame(png, 1).is_err());
    assert!(Pna.decode(&png[..8]).is_err());
    Ok(())
}
