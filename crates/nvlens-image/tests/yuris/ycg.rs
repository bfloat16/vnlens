#![allow(clippy::unwrap_used)]

use super::*;
use nvlens_io::BinaryWriter;
#[test]
fn decodes_bgra_and_preserves_png_offsets() {
    let mut bytes = vec![0; 56];
    bytes[..4].copy_from_slice(b"YCG\0");
    for (offset, value) in [(4, 2), (8, 1), (12, 32)] {
        BinaryWriter::u32_le(value, &mut bytes[offset..]);
    }
    bytes.extend([0, 0, 255, 255, 255, 0, 0, 128]);
    let mut image = decode(&bytes).unwrap();
    image.meta.offset_x = -3;
    image.meta.offset_y = 5;
    let png = image.to_png().unwrap();
    let decoded = crate::decode_as("image/standard", &png).unwrap();
    assert_eq!(decoded.meta, image.meta);
    let PixelBuffer::Rgba8(pixels) = decoded.pixels else {
        return;
    };
    assert_eq!(pixels, [255, 0, 0, 255, 0, 0, 255, 128]);
    for end in 4..bytes.len() {
        assert!(decode(&bytes[..end]).is_err());
    }
}
#[test]
fn reads_independent_zlib_blocks() {
    // Independent Python zlib vectors for one red and one blue BGRA pixel.
    let mut bytes = vec![0; 56];
    bytes[..4].copy_from_slice(b"YCG\0");
    for (offset, value) in [
        (4, 2),
        (8, 1),
        (12, 32),
        (16, 1),
        (32, 4),
        (36, 12),
        (48, 4),
        (52, 12),
    ] {
        BinaryWriter::u32_le(value, &mut bytes[offset..]);
    }
    bytes.extend([0x78, 0x9c, 0x63, 0x60, 0xf8, 0xff, 0x1f, 0, 3, 1, 1, 0xff]);
    bytes.extend([0x78, 0x9c, 0xfb, 0xcf, 0xc0, 0xd0, 0, 0, 4, 0x80, 1, 0x80]);
    let image = decode(&bytes).unwrap();
    assert!(
        matches!(image.pixels,PixelBuffer::Bgra8(ref pixels) if pixels==&[0,0,255,255,255,0,0,128])
    );
    bytes[79] ^= 1;
    assert!(decode(&bytes).is_err());
}
