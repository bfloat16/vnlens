#![allow(clippy::unwrap_used)]

use super::*;
use nvlens_io::BinaryWriter;

fn raw(flags: u32, depth: u32, colors: &[u8], alpha: &[u8], palette: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 36];
    for (i, value) in [
        0x1a55_5947,
        0x0100_0000 | flags,
        u32::MAX,
        depth,
        1,
        2,
        colors.len() as u32,
        alpha.len() as u32,
        (palette.len() / 4) as u32,
    ]
    .into_iter()
    .enumerate()
    {
        BinaryWriter::u32_le(value, &mut bytes[i * 4..]);
    }
    bytes.extend_from_slice(palette);
    bytes.extend_from_slice(colors);
    bytes.extend_from_slice(alpha);
    bytes
}

#[test]
fn raw_bottom_up_rows_palette_and_alpha_precision() {
    let data = raw(
        3,
        24,
        &[1, 2, 3, 0, 4, 5, 6, 0],
        &[7, 0, 0, 0, 8, 0, 0, 0],
        &[],
    );
    let PixelBuffer::Rgba8(pixels) = decode(&data).unwrap().pixels else {
        return;
    };
    assert_eq!(pixels, [6, 5, 4, 8, 3, 2, 1, 7]);
    let data = raw(
        1,
        8,
        &[1, 0, 0, 0, 0, 0, 0, 0],
        &[16, 0, 0, 0, 8, 0, 0, 0],
        &[1, 2, 3, 0, 4, 5, 6, 0],
    );
    let PixelBuffer::Rgba8(pixels) = decode(&data).unwrap().pixels else {
        return;
    };
    assert_eq!(pixels, [3, 2, 1, 128, 6, 5, 4, 255]);
    for len in [3, 35, data.len() - 1] {
        assert!(decode(&data[..len]).is_err());
    }
    let mut invalid = data.clone();
    invalid[44] = 2;
    assert!(decode(&invalid).is_err());
}
