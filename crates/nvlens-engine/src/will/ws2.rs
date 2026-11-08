//! AdvHD parameter tables, located through decoded x64 MOVZX/LEA/MOV
//! table access. Each byte opcode indexes one pointer to signed type tags,
//! terminated by a negative byte; null pointers denote undefined opcodes.

use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use nvlens_core::{Error, Result};
use nvlens_io::{BinaryReader, pe::PeImage};
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) fn table(pe: &PeImage<'_>, cancel: &AtomicBool) -> Result<Option<Vec<u8>>> {
    if pe.machine != 0x8664 {
        return Ok(None);
    }
    let mut result = None;
    for section in pe.sections.iter().filter(|s| s.executable) {
        let data = pe.section_data(section)?;
        let mut decoder = Decoder::with_ip(
            64,
            data,
            pe.image_base + u64::from(section.virtual_address),
            DecoderOptions::NONE,
        );
        let mut previous = iced_x86::Instruction::default();
        let mut decoded = 0usize;
        while decoder.can_decode() {
            if decoded.is_multiple_of(1024) && cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            decoded += 1;
            let current = decoder.decode();
            if previous.mnemonic() == Mnemonic::Movzx
                && previous.op0_kind() == OpKind::Register
                && previous.op1_kind() == OpKind::Register
                && matches!(
                    previous.op1_register(),
                    Register::AL
                        | Register::CL
                        | Register::DL
                        | Register::BL
                        | Register::SPL
                        | Register::BPL
                        | Register::SIL
                        | Register::DIL
                        | Register::R8L
                        | Register::R9L
                        | Register::R10L
                        | Register::R11L
                        | Register::R12L
                        | Register::R13L
                        | Register::R14L
                        | Register::R15L
                )
                && current.mnemonic() == Mnemonic::Lea
                && current.op0_kind() == OpKind::Register
                && current.is_ip_rel_memory_operand()
            {
                let mut tail = Decoder::with_ip(
                    64,
                    &data[decoder.position()..],
                    current.next_ip(),
                    DecoderOptions::NONE,
                );
                let load = tail.decode();
                if load.mnemonic() == Mnemonic::Mov
                    && load.op1_kind() == OpKind::Memory
                    && load.memory_base() == current.op0_register()
                    && load.memory_index_scale() == 8
                    && load.memory_index() == wide(previous.op0_register())
                    && load.memory_displacement64() == 0
                    && load.op0_register() == current.op0_register()
                    && let Some(candidate) = read_table(pe, current.ip_rel_memory_address())
                {
                    if result.as_ref().is_some_and(|old| old != &candidate) {
                        return Err(Error::UnknownScheme(Some(
                            "Conflicting AdvHD WS2 parameter tables".into(),
                        )));
                    }
                    result = Some(candidate);
                }
            }
            previous = current;
        }
    }
    Ok(result)
}

fn read_table(pe: &PeImage<'_>, address: u64) -> Option<Vec<u8>> {
    let mut pointers = BinaryReader::new(pe.at_va(address)?);
    let mut out = Vec::new();
    let mut defined = false;
    for _ in 0..256 {
        let address = pointers.read_u64_le().ok()?;
        if address == 0 {
            out.push(0xfe);
            continue;
        }
        let bytes = pe.at_va(address)?;
        let end = bytes.iter().position(|&b| b >= 128)?;
        let schema = &bytes[..end];
        if !valid_schema(schema) {
            return None;
        }
        defined |= !schema.is_empty();
        out.extend_from_slice(schema);
        out.push(0xff);
    }
    defined.then_some(out)
}

fn valid_schema(schema: &[u8]) -> bool {
    let mut i = 0;
    while let Some(&kind) = schema.get(i) {
        match kind {
            0..=5 | 8 => i += 1,
            6 | 9 | 10 if schema.get(i + 1) == Some(&8) => i += 2,
            7 => return i + 2 == schema.len() && matches!(schema[i + 1], 0..=6 | 9),
            _ => return false,
        }
    }
    true
}

fn wide(register: Register) -> Register {
    match register {
        Register::EAX => Register::RAX,
        Register::ECX => Register::RCX,
        Register::EDX => Register::RDX,
        Register::EBX => Register::RBX,
        Register::ESP => Register::RSP,
        Register::EBP => Register::RBP,
        Register::ESI => Register::RSI,
        Register::EDI => Register::RDI,
        Register::R8D => Register::R8,
        Register::R9D => Register::R9,
        Register::R10D => Register::R10,
        Register::R11D => Register::R11,
        Register::R12D => Register::R12,
        Register::R13D => Register::R13,
        Register::R14D => Register::R14,
        Register::R15D => Register::R15,
        other => other,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;

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
                0x41, 0x0f, 0xb6, 0xc0, 0x4c, 0x8d, 0x35, 0xf5, 0, 0, 0, 0x4d, 0x8b, 0x34, 0xc6,
                0xc3,
            ]
        } else {
            [
                0x41, 0x0f, 0xb6, 0xc0, 0x48, 0x8d, 0x1d, 0xf5, 0, 0, 0, 0x48, 0x8b, 0x1c, 0xc3,
                0xc3,
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
}
