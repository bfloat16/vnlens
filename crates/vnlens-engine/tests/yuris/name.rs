#![allow(clippy::unwrap_used)]

use super::*;
use vnlens_io::BinaryWriter;

fn filename_decoder(base: u32, xor: Option<u8>) -> Vec<u8> {
    let mut bytes = vec![0; 0x600];
    bytes[..2].copy_from_slice(b"MZ");
    BinaryWriter::u32_le(0x80, &mut bytes[0x3c..]);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    BinaryWriter::u16_le(0x14c, &mut bytes[0x84..]);
    BinaryWriter::u16_le(1, &mut bytes[0x86..]);
    BinaryWriter::u16_le(0xe0, &mut bytes[0x94..]);
    BinaryWriter::u16_le(0x10b, &mut bytes[0x98..]);
    BinaryWriter::u32_le(base, &mut bytes[0xb4..]);
    BinaryWriter::u32_le(0x200, &mut bytes[0xd4..]);
    BinaryWriter::u32_le(0x1000, &mut bytes[0x184..]);
    BinaryWriter::u32_le(0x400, &mut bytes[0x188..]);
    BinaryWriter::u32_le(0x200, &mut bytes[0x18c..]);
    BinaryWriter::u32_le(0x2000_0000, &mut bytes[0x19c..]);
    // MOVSX EAX,[ESP+EDX+0x20]; NEG/DEC; store AL; counted loop.
    let mut code = vec![
        0x0f, 0xbe, 0x44, 0x14, 0x20, 0xf7, 0xd8, 0x48, 0x88, 0x44, 0x14, 0x20, 0x42, 0x3b, 0xd5,
        0x7c, 0xef,
    ];
    if let Some(key) = xor {
        code.extend_from_slice(&[
            0x85, 0xed, 0x7e, 0x0c, 0x33, 0xd2, 0x80, 0x74, 0x14, 0x20, key, 0x42, 0x3b, 0xd5,
            0x7c, 0xf6,
        ]);
    }
    code.extend_from_slice(&[0x8d, 0x54, 0x24, 0x20, 0x52, 0x68]);
    let mut address = [0; 4];
    BinaryWriter::u32_le(base + 0x1280, &mut address);
    code.extend_from_slice(&address);
    code.extend_from_slice(&[0xe8, 0, 0, 0, 0]);
    bytes[0x350..0x350 + code.len()].copy_from_slice(&code);
    bytes[0x480..0x490].copy_from_slice(b"ysbin\\yscfg.ybn\0");
    bytes
}

#[test]
fn filename_key_requires_buffer_dataflow_and_comparison_anchor() {
    for base in [0x400000, 0x10000000] {
        for extra in [None, Some(0), Some(0x53)] {
            let mut bytes = filename_decoder(base, extra);
            let image = PeImage::parse(&bytes).unwrap().unwrap();
            let key = from_image(&image, &AtomicBool::new(false))
                .unwrap()
                .unwrap();
            assert_eq!(key.bytes(), [0xff ^ extra.unwrap_or(0)]);
            assert!(matches!(
                from_image(&image, &AtomicBool::new(true)),
                Err(Error::Cancelled)
            ));
            // Break the back edge, then the comparison string.
            bytes[0x360] ^= 1;
            let image = PeImage::parse(&bytes).unwrap().unwrap();
            assert!(
                from_image(&image, &AtomicBool::new(false))
                    .unwrap()
                    .is_none()
            );
            bytes[0x360] ^= 1;
            bytes[0x480] = b'X';
            let image = PeImage::parse(&bytes).unwrap().unwrap();
            assert!(
                from_image(&image, &AtomicBool::new(false))
                    .unwrap()
                    .is_none()
            );
        }
    }
}
