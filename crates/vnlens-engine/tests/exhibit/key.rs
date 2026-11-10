#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn ini_checksum_uses_raw_bytes_and_versioned_field_order() {
    let base =
        b"[setting]\r\nCLASS=ABCD\r\nTITLE=ignored\r\nSYSVER=1\r\nW_VIEW=12\r\nH_VIEW=34\r\n";
    assert_eq!(ini_checksum(base).unwrap(), 0x7876_7472);
    assert_eq!(
        ini_checksum(b"[setting]\nCLASS=ABCD\nTITLE=1234\n").unwrap(),
        0x7876_7472
    );
    assert_eq!(
        ini_checksum(b"[setting]\nCLASS=\x82\xa0\nSYSVER=1\n").unwrap(),
        0xa082
    );
    assert_eq!(
        ini_checksum(b"[setting]\nSYSVER=1\nFLAGS=4\nGUID=ABC\nSVDATA=D\n").unwrap(),
        0x4342_4178
    );
}

#[test]
fn key_bitmap_coordinates_and_orientation() {
    for (depth, height) in [(24u16, 40i32), (32, 40), (24, -40)] {
        let stride = 40 * usize::from(depth / 8);
        let mut data = vec![0; 40 + stride * 40];
        BinaryWriter::u32_le(40, &mut data);
        BinaryWriter::u32_le(40, &mut data[4..]);
        BinaryWriter::u32_le(height as u32, &mut data[8..]);
        BinaryWriter::u16_le(1, &mut data[12..]);
        BinaryWriter::u16_le(depth, &mut data[14..]);
        for y in 0..32 {
            let row = if height > 0 { 39 - y } else { y };
            data[40 + row * stride + 31 * usize::from(depth / 8)] =
                ((0xa5c3_718eu32 >> y) & 1) as u8;
        }
        assert_eq!(bitmap_word(&data).unwrap(), 0xa5c3_718e);
        assert!(bitmap_word(&data[..40]).is_err());
    }
}
