#![allow(clippy::unwrap_used)]

use super::*;
use vnlens_io::BinaryWriter;

fn fixture(base: u64, register: u8) -> Vec<u8> {
    let mut data = vec![0; 0x1600];
    data[..2].copy_from_slice(b"MZ");
    BinaryWriter::u32_le(0x80, &mut data[0x3c..]);
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    BinaryWriter::u16_le(0x8664, &mut data[0x84..]);
    BinaryWriter::u16_le(1, &mut data[0x86..]);
    BinaryWriter::u16_le(0xf0, &mut data[0x94..]);
    BinaryWriter::u16_le(0x20b, &mut data[0x98..]);
    BinaryWriter::u64_le(base, &mut data[0xb0..]);
    BinaryWriter::u32_le(0x200, &mut data[0xd4..]);
    BinaryWriter::u32_le(0x1000, &mut data[0x194..]);
    BinaryWriter::u32_le(0x1400, &mut data[0x198..]);
    BinaryWriter::u32_le(0x200, &mut data[0x19c..]);
    BinaryWriter::u32_le(0x60000020, &mut data[0x1ac..]);
    let code = if register == 14 {
        [
            0x41, 0x0f, 0xb6, 0xc0, 0x4c, 0x8d, 0x35, 0xf5, 0, 0, 0, 0x4d, 0x8b, 0x34, 0xc6, 0xc3,
        ]
    } else {
        [
            0x41, 0x0f, 0xb6, 0xc0, 0x48, 0x8d, 0x1d, 0xf5, 0, 0, 0, 0x48, 0x8b, 0x1c, 0xc3, 0xc3,
        ]
    };
    data[0x200..0x210].copy_from_slice(&code);
    for i in 0..256 {
        BinaryWriter::u64_le(base + 0x1900, &mut data[0x300 + i * 8..]);
    }
    data[0xb00..0xb03].copy_from_slice(&[6, 8, 255]);
    data
}
#[test]
fn x64_table_detection_follows_relocated_operands_and_registers() {
    for (base, reg) in [(0x140000000, 14), (0x180000000, 3)] {
        let bytes = fixture(base, reg);
        let image = PeImage::parse(&bytes).unwrap().unwrap();
        let schema = table(&image, &AtomicBool::new(false)).unwrap().unwrap();
        assert_eq!(schema, [6, 8, 255].repeat(256));
        assert!(matches!(
            table(&image, &AtomicBool::new(true)),
            Err(Error::Cancelled)
        ));
    }
    let mut bytes = fixture(0x140000000, 14);
    bytes[0x20e] = 0xce; // REX/SIB now indexes RCX, unlike the MOVZX destination.
    assert!(
        table(
            &PeImage::parse(&bytes).unwrap().unwrap(),
            &AtomicBool::new(false)
        )
        .unwrap()
        .is_none()
    );
}
#[test]
fn schema_terminators_strings_and_repeat_rules() {
    assert!(valid_schema(&[6, 8, 1, 7, 9]));
    assert!(!valid_schema(&[6]));
    assert!(!valid_schema(&[7, 7]));
    assert!(!valid_schema(&[11]));
    let mut bytes = fixture(0x140000000, 14);
    BinaryWriter::u64_le(0, &mut bytes[0x300..]);
    let schema = table(
        &PeImage::parse(&bytes).unwrap().unwrap(),
        &AtomicBool::new(false),
    )
    .unwrap()
    .unwrap();
    assert_eq!(schema[0], 254);
}

fn x86_fixture(base: u32, between: &[u8], load: &[u8]) -> Vec<u8> {
    let mut data = vec![0; 0x1000];
    data[..2].copy_from_slice(b"MZ");
    BinaryWriter::u32_le(0x80, &mut data[0x3c..]);
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    BinaryWriter::u16_le(0x14c, &mut data[0x84..]);
    BinaryWriter::u16_le(1, &mut data[0x86..]);
    BinaryWriter::u16_le(0xe0, &mut data[0x94..]);
    BinaryWriter::u16_le(0x10b, &mut data[0x98..]);
    for (at, value) in [
        (0xb4, base),
        (0xd4, 0x200),
        (0x180, 0xe00),
        (0x184, 0x1000),
        (0x188, 0xe00),
        (0x18c, 0x200),
        (0x19c, 0x60000020),
    ] {
        BinaryWriter::u32_le(value, &mut data[at..]);
    }
    // MOVZX EAX, byte ptr [ESP+0x4c]; optional intervening instructions;
    // MOV <destination>, [EAX*4+table]. Model sub_4E4890's stack argument.
    let mut code = vec![0x0f, 0xb6, 0x44, 0x24, 0x4c];
    code.extend_from_slice(between);
    code.extend_from_slice(load);
    let address_at = code.len();
    code.resize(address_at + 4, 0);
    BinaryWriter::u32_le(base + 0x1100, &mut code[address_at..]);
    code.push(0xc3);
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    for i in 0..256 {
        BinaryWriter::u32_le(base + 0x1500, &mut data[0x300 + i * 4..]);
    }
    data[0x700..0x703].copy_from_slice(&[6, 8, 255]);
    data
}

#[test]
fn x86_table_follows_opcode_across_stack_writes_and_destination_changes() {
    for base in [0x400000, 0x710000] {
        for (between, load) in [
            (&[][..], &[0x8b, 0x04, 0x85][..]), // MOV EAX, [EAX*4+table]
            (&[0x89, 0x5c, 0x24, 0x40][..], &[0x8b, 0x2c, 0x85][..]), // MOV EBP
        ] {
            let bytes = x86_fixture(base, between, load);
            let pe = PeImage::parse(&bytes).unwrap().unwrap();
            assert_eq!(
                table(&pe, &AtomicBool::new(false)).unwrap().unwrap(),
                [6, 8, 255].repeat(256)
            );
            assert!(matches!(
                table(&pe, &AtomicBool::new(true)),
                Err(Error::Cancelled)
            ));
        }
    }
}

#[test]
fn x86_table_rejects_clobbered_indices_and_control_flow_boundaries() {
    for between in [
        &[0xb0, 0][..],          // MOV AL, 0
        &[0xb4, 0][..],          // MOV AH, 0
        &[0x66, 0x31, 0xc0][..], // XOR AX, AX
        &[0x31, 0xc0][..],       // XOR EAX, EAX
        &[0xf7, 0xe1][..],       // MUL ECX writes EAX implicitly
        &[0x74, 0][..],          // JZ
        &[0xeb, 0][..],          // JMP
        &[0xe8, 0, 0, 0, 0][..], // CALL
        &[0xc3][..],             // RET
    ] {
        let bytes = x86_fixture(0x400000, between, &[0x8b, 0x2c, 0x85]);
        let pe = PeImage::parse(&bytes).unwrap().unwrap();
        assert!(table(&pe, &AtomicBool::new(false)).unwrap().is_none());
    }
    let bytes = x86_fixture(0x400000, &[], &[0x8b, 0x2c, 0x8d]); // ECX index
    let pe = PeImage::parse(&bytes).unwrap().unwrap();
    assert!(table(&pe, &AtomicBool::new(false)).unwrap().is_none());
}

#[test]
fn x86_table_validates_all_pointers_and_parameter_types() {
    for (offset, value) in [(0x6fc, 0x500000), (0x700, 11)] {
        let mut bytes = x86_fixture(0x400000, &[], &[0x8b, 0x04, 0x85]);
        BinaryWriter::u32_le(value, &mut bytes[offset..]);
        let pe = PeImage::parse(&bytes).unwrap().unwrap();
        assert!(table(&pe, &AtomicBool::new(false)).unwrap().is_none());
    }
}
