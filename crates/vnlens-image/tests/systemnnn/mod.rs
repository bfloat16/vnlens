#![allow(clippy::unwrap_used)]

use super::*;
use vnlens_io::BinaryWriter;
fn envelope(payload: &[u8], kind: u8, width: u32, height: u32) -> Vec<u8> {
    let mut data = vec![b' '; 64];
    data[..4].copy_from_slice(if kind == 8 { b"PNG " } else { b"BMP " });
    BinaryWriter::u32_le(width, &mut data[36..]);
    BinaryWriter::u32_le(height, &mut data[40..]);
    let field = format!("PACKTYPE={kind}");
    data[48..48 + field.len()].copy_from_slice(field.as_bytes());
    data.extend_from_slice(payload);
    data
}
fn bmp(depth: u16, width: u32, height: u32, palette: &[u8], rows: &[u8]) -> Vec<u8> {
    let mut data = vec![0; 54];
    data[..2].copy_from_slice(b"BM");
    // Converter fields intentionally differ from physical storage.
    BinaryWriter::u32_le(999, &mut data[2..]);
    BinaryWriter::u32_le(777, &mut data[10..]);
    BinaryWriter::u32_le(40, &mut data[14..]);
    BinaryWriter::u32_le(width, &mut data[18..]);
    BinaryWriter::u32_le(height, &mut data[22..]);
    BinaryWriter::u16_le(1, &mut data[26..]);
    BinaryWriter::u16_le(depth, &mut data[28..]);
    BinaryWriter::u32_le((palette.len() / 4) as u32, &mut data[46..]);
    data.extend_from_slice(palette);
    data.extend_from_slice(rows);
    data
}
#[test]
fn indexed_bmp_uses_sequential_palette_top_down_rows_and_no_resource_conflict() {
    let payload = bmp(
        8,
        3,
        2,
        &[0, 0, 255, 0, 255, 0, 0, 0],
        &[0, 1, 0, 99, 1, 0, 1, 99],
    );
    let data = envelope(&payload, 0, 3, 2);
    let expected = vec![
        255, 0, 0, 255, 0, 0, 255, 255, 255, 0, 0, 255, 0, 0, 255, 255, 255, 0, 0, 255, 0, 0, 255,
        255,
    ];
    let image = crate::decode_as("dwq/systemnnn", &data).unwrap();
    assert!(matches!(image.pixels,PixelBuffer::Rgba8(p) if p==expected));
    for len in 0..data.len() {
        assert!(Dwq.decode(&data[..len]).is_err());
    }
    let mut bad = data.clone();
    bad[64 + 54 + 8] = 2;
    assert!(Dwq.decode(&bad).is_err());
    let mut bad = data;
    BinaryWriter::u32_le(4, &mut bad[36..]);
    assert!(Dwq.metadata(&bad).is_err());
}
#[test]
fn bmp_rgb565_rgb24_rgb32_and_legacy_header() {
    for (depth, bytes, expected) in [
        (16, vec![0x1f, 0, 0, 0], vec![0, 0, 255, 255]),
        (24, vec![10, 20, 30, 0], vec![10, 20, 30, 255]),
        (32, vec![10, 20, 30, 0], vec![10, 20, 30, 255]),
    ] {
        let mut data = envelope(&bmp(depth, 1, 1, &[], &bytes), 0, 1, 1);
        assert!(matches!(Dwq.decode(&data).unwrap().pixels,PixelBuffer::Rgba8(p) if p==expected));
        data[..48].copy_from_slice(b"IF PACKTYPE==0  CUT THIS 64 BYTETHEN REMAKE BMP ");
        assert!(matches!(Dwq.decode(&data).unwrap().pixels,PixelBuffer::Rgba8(p) if p==expected));
    }
}
#[test]
fn png_preserves_alpha_offsets_and_rejects_outer_dimension_mismatch() {
    let image = Image {
        meta: ImageMeta {
            width: 1,
            height: 1,
            offset_x: -3,
            offset_y: 7,
            offset_unit: OffsetUnit::Pixels,
            bpp: 32,
        },
        pixels: PixelBuffer::Rgba8(vec![1, 2, 3, 4]),
    };
    let mut data = envelope(&image.to_png().unwrap(), 8, 1, 1);
    let decoded = Dwq.decode(&data).unwrap();
    assert_eq!(decoded.meta, image.meta);
    assert!(matches!(decoded.pixels,PixelBuffer::Rgba8(p) if p==[1,2,3,4]));
    data[58] = b'A';
    assert!(Dwq.decode(&data).is_ok());
    BinaryWriter::u32_le(2, &mut data[40..]);
    assert!(Dwq.decode(&data).is_err());
    assert!(Dwq.metadata(b"not an image").unwrap().is_none());
}
