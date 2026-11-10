#![allow(clippy::unwrap_used)]

use super::*;
use vnlens_io::BinaryWriter;
fn word(data: &mut Vec<u8>, value: u32) {
    let mut bytes = [0; 4];
    BinaryWriter::u32_le(value, &mut bytes);
    data.extend(bytes);
}
fn sample() -> Vec<u8> {
    let mut data = Vec::new();
    for value in [0x103, 2, 1, 5, 0x802, 33, 0, 0x544c44, 0xe02, 1024] {
        word(&mut data, value);
    }
    let mut palette = vec![0; 1024];
    palette[4..8].copy_from_slice(&[1, 2, 3, 0]);
    palette[8..12].copy_from_slice(&[4, 5, 6, 0]);
    data.extend(palette);
    for value in [0x4f02, 2, 2] {
        word(&mut data, value);
    }
    data.extend([1, 2, 255, 128]);
    for value in [0x17200, 2, 0, 0, 2, 1, 2] {
        word(&mut data, value);
    }
    data.extend([0, 1, 254, 0]);
    for value in [0x10004, 0, 0x8000] {
        word(&mut data, value);
    }
    data
}
#[test]
fn palette_and_end_are_not_frames_and_deltas_preserve_color_and_alpha() {
    let bytes = sample();
    assert_eq!(Dlt.frame_count(&bytes).unwrap(), 3);
    let PixelBuffer::Rgba8(first) = Dlt.decode_frame(&bytes, 0).unwrap().pixels else {
        return;
    };
    assert_eq!(first, [3, 2, 1, 255, 6, 5, 4, 128]);
    for index in [1, 2] {
        let PixelBuffer::Rgba8(pixels) = Dlt.decode_frame(&bytes, index).unwrap().pixels else {
            return;
        };
        assert_eq!(pixels, [3, 2, 1, 255, 3, 2, 1, 0]);
    }
    assert!(Dlt.decode_frame(&bytes, 3).is_err());
    assert!(Dlt.frame_count(&bytes[..bytes.len() - 1]).is_err());
    let mut invalid = bytes;
    BinaryWriter::u32_le(3, &mut invalid[1088..]);
    assert!(Dlt.frame_count(&invalid).is_err());
}
