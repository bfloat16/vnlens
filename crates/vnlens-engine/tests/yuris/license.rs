#![allow(clippy::unwrap_used)]

use super::*;
use vnlens_io::BinaryWriter;

fn executable(base: u32, constant: u32, loop_count: usize) -> Vec<u8> {
    let mut b = vec![0; 0x600];
    b[..2].copy_from_slice(b"MZ");
    BinaryWriter::u32_le(0x80, &mut b[0x3c..]);
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    BinaryWriter::u16_le(0x14c, &mut b[0x84..]);
    BinaryWriter::u16_le(1, &mut b[0x86..]);
    BinaryWriter::u16_le(0xe0, &mut b[0x94..]);
    BinaryWriter::u16_le(0x10b, &mut b[0x98..]);
    BinaryWriter::u32_le(base, &mut b[0xb4..]);
    BinaryWriter::u32_le(0x200, &mut b[0xd4..]);
    BinaryWriter::u32_le(0x1000, &mut b[0x184..]);
    BinaryWriter::u32_le(0x400, &mut b[0x188..]);
    BinaryWriter::u32_le(0x200, &mut b[0x18c..]);
    BinaryWriter::u32_le(0x2000_0000, &mut b[0x19c..]);
    let source = base + 0x4100;
    let destination = base + 0x4200;
    let mut code = Vec::new();
    // MOV dword ptr [source], constant
    code.extend_from_slice(&[0xc7, 0x05]);
    let mut word = [0; 4];
    BinaryWriter::u32_le(source, &mut word);
    code.extend_from_slice(&word);
    BinaryWriter::u32_le(constant, &mut word);
    code.extend_from_slice(&word);
    // MOV EAX, [source]; serialize big-endian bytes into [destination..+4]
    code.push(0xa1);
    BinaryWriter::u32_le(source, &mut word);
    code.extend_from_slice(&word);
    for (index, shift) in [24u8, 16, 8].into_iter().enumerate() {
        code.extend_from_slice(&[0x8b, 0xd0, 0xc1, 0xea, shift, 0x88, 0x15]);
        BinaryWriter::u32_le(destination + index as u32, &mut word);
        code.extend_from_slice(&word);
    }
    code.push(0xa2);
    BinaryWriter::u32_le(destination + 3, &mut word);
    code.extend_from_slice(&word);
    // Counted 4-byte XOR loop referencing [ECX + destination]
    let mut xor_loop = vec![
        0x46, 0x8b, 0xcb, 0x83, 0xe1, 0x03, 0x0f, 0xb6, 0x89, 0, 0, 0, 0, 0x30, 0x4e, 0xff, 0x43,
        0x3b, 0xdf, 0x7c, 0xeb,
    ];
    BinaryWriter::u32_le(destination, &mut xor_loop[9..]);
    for _ in 0..loop_count {
        code.extend_from_slice(&xor_loop);
    }
    b[0x200..0x200 + code.len()].copy_from_slice(&code);
    b
}

#[test]
fn immediate_slot_serialization_requires_all_four_section_xor_loops() {
    for base in [0x400000, 0x10000000] {
        let bytes = executable(base, 0x1234_5678, 4);
        let image = PeImage::parse(&bytes).unwrap().unwrap();
        let key = from_image(&image, &AtomicBool::new(false))
            .unwrap()
            .unwrap();
        assert_eq!(key.bytes(), [0x12, 0x34, 0x56, 0x78]);
        assert!(matches!(
            from_image(&image, &AtomicBool::new(true)),
            Err(Error::Cancelled)
        ));
        let fewer = executable(base, 0x1234_5678, 3);
        let image = PeImage::parse(&fewer).unwrap().unwrap();
        assert!(
            from_image(&image, &AtomicBool::new(false))
                .unwrap()
                .is_none()
        );
    }
}
