//! Relocated x86 YU-RIS product string, CRC32 call and big-endian key stores.
//! Decode instructions and verify the string-length loop and output dataflow;
//! no executable opcode bytes or fixed image addresses are matched.
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use nvlens_core::{Error, Result, Secret};
use nvlens_crypto::checksum::crc32;
use nvlens_io::{BinaryReader, BinaryWriter, pe::PeImage};
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) fn from_pe(bytes: &[u8], cancel: &AtomicBool) -> Result<Option<Secret>> {
    let Some(mut pe) = PeImage::parse(bytes)? else {
        return Ok(None);
    };
    if pe.machine != 0x14c {
        return Ok(None);
    }
    nvlens_unpack::steamstub::unpack(&mut pe, cancel)?;
    let mut found = None;
    for section in pe.sections.iter().filter(|s| s.executable) {
        let code = pe.section_data(section)?;
        for start in 0..code.len() {
            if start.is_multiple_of(4096) && cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let mut decoder =
                Decoder::with_ip(32, &code[start..], start as u64, DecoderOptions::NONE);
            let first = decoder.decode();
            if first.mnemonic() != Mnemonic::Mov
                || first.op0_kind() != OpKind::Register
                || first.op1_kind() != OpKind::Memory
                || !absolute(&first)
            {
                continue;
            }
            let mut p = [Instruction::default(); 24];
            p[0] = first;
            for i in &mut p[1..] {
                *i = decoder.decode();
            }
            if !initialization(&p) {
                continue;
            }
            let slot = u64::from(first.memory_displacement32());
            let Some(pointer) = pe.at_va(slot).filter(|b| b.len() >= 4) else {
                continue;
            };
            let Some(product) = pe.c_string_at_va(u64::from(BinaryReader::u32_le(pointer))) else {
                continue;
            };
            let mut bytes = [0; 4];
            BinaryWriter::u32_be(crc32::ieee(0, product), &mut bytes);
            let key = Secret::new(bytes);
            if found.as_ref().is_some_and(|old| old != &key) {
                return Err(Error::UnknownScheme(Some(
                    "Conflicting YU-RIS initialization instructions".into(),
                )));
            }
            found = Some(key);
        }
    }
    Ok(found)
}
fn absolute(i: &Instruction) -> bool {
    i.memory_base() == Register::None && i.memory_index() == Register::None
}
fn regs(i: &Instruction, op: Mnemonic, dst: Register, src: Register) -> bool {
    i.mnemonic() == op
        && i.op0_kind() == OpKind::Register
        && i.op1_kind() == OpKind::Register
        && i.op0_register() == dst
        && i.op1_register() == src
}
fn byte_load(i: &Instruction, pointer: Register) -> bool {
    i.mnemonic() == Mnemonic::Mov
        && i.op0_kind() == OpKind::Register
        && i.op1_kind() == OpKind::Memory
        && i.memory_base() == pointer
        && i.memory_index() == Register::None
        && i.memory_displacement32() == 0
        && i.memory_size() == iced_x86::MemorySize::UInt8
}
fn initialization(p: &[Instruction; 24]) -> bool {
    use Mnemonic as M;
    use Register as R;
    let pointer = p[0].op0_register();
    if !regs(&p[1], M::Xor, R::EAX, R::EAX)
        || !byte_load(&p[2], pointer)
        || !regs(&p[3], M::Mov, R::ECX, pointer)
        || !regs(&p[4], M::Test, p[2].op0_register(), p[2].op0_register())
        || p[5].mnemonic() != M::Je
        || p[5].near_branch_target() != p[11].ip()
        || p[6].mnemonic() != M::Inc
        || p[6].op0_register() != R::ECX
        || p[7].mnemonic() != M::Inc
        || p[7].op0_register() != R::EAX
        || !byte_load(&p[8], R::ECX)
        || !regs(&p[9], M::Test, p[8].op0_register(), p[8].op0_register())
        || p[10].mnemonic() != M::Jne
        || p[10].near_branch_target() != p[6].ip()
        || !regs(&p[11], M::Mov, R::EDX, R::EAX)
        || !regs(&p[12], M::Mov, R::EAX, pointer)
        || p[13].mnemonic() != M::Call
        || p[13].op0_kind() != OpKind::NearBranch32
    {
        return false;
    }
    let destination = p[16].memory_displacement32();
    for (index, shift, byte) in [(0, 24, R::DL), (1, 16, R::CL), (2, 8, R::DL)] {
        let at = 14 + index * 3;
        let register = if byte == R::CL { R::ECX } else { R::EDX };
        if !regs(&p[at], M::Mov, register, R::EAX)
            || p[at + 1].mnemonic() != M::Shr
            || p[at + 1].op0_register() != register
            || p[at + 1].op1_kind() != OpKind::Immediate8
            || p[at + 1].immediate8() != shift
            || !store(&p[at + 2], destination.checked_add(index as u32), byte)
        {
            return false;
        }
    }
    store(&p[23], destination.checked_add(3), R::AL)
}
fn store(i: &Instruction, address: Option<u32>, byte: Register) -> bool {
    i.mnemonic() == Mnemonic::Mov
        && i.op0_kind() == OpKind::Memory
        && absolute(i)
        && Some(i.memory_displacement32()) == address
        && i.op1_register() == byte
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn executable(base: u32) -> Vec<u8> {
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
        let signature = &mut b[0x200..0x247];
        signature[..2].copy_from_slice(&[0x8b, 0x3d]);
        signature[6..29].copy_from_slice(&[
            0x33, 0xc0, 0x8a, 0x37, 0x8b, 0xcf, 0x84, 0xf6, 0x74, 8, 0x41, 0x40, 0x8a, 0x11, 0x84,
            0xd2, 0x75, 0xf8, 0x8b, 0xd0, 0x8b, 0xc7, 0xe8,
        ]);
        signature[33..40].copy_from_slice(&[0x8b, 0xd0, 0xc1, 0xea, 0x18, 0x88, 0x15]);
        signature[44..51].copy_from_slice(&[0x8b, 0xc8, 0xc1, 0xe9, 0x10, 0x88, 0x0d]);
        signature[55..62].copy_from_slice(&[0x8b, 0xd0, 0xc1, 0xea, 8, 0x88, 0x15]);
        signature[66] = 0xa2;
        BinaryWriter::u32_le(base + 0x1100, &mut signature[2..]);
        for (offset, index) in [(40, 0), (51, 1), (62, 2), (67, 3)] {
            BinaryWriter::u32_le(base + 0x4000 + index, &mut signature[offset..]);
        }
        BinaryWriter::u32_le(base + 0x1120, &mut b[0x300..]);
        b[0x320..0x32a].copy_from_slice(b"123456789\0");
        b
    }

    #[test]
    fn scans_relocated_pe_without_game_name_or_fixed_key() {
        for base in [0x400000, 0x10000000] {
            let bytes = executable(base);
            let key = from_pe(&bytes, &AtomicBool::new(false)).unwrap().unwrap();
            assert_eq!(key.bytes(), [0xcb, 0xf4, 0x39, 0x26]);
            let mut data = vec![0; 7];
            nvlens_crypto::cipher::xor::apply_u32_key(&mut data, key.bytes().try_into().unwrap());
            assert_eq!(data, [0xcb, 0xf4, 0x39, 0x26, 0xcb, 0xf4, 0x39]);
            nvlens_crypto::cipher::xor::apply_u32_key(&mut data, key.bytes().try_into().unwrap());
            assert_eq!(data, [0; 7]);
            for end in 0..bytes.len() {
                let _ = from_pe(&bytes[..end], &AtomicBool::new(false));
            }
        }
        let mut bytes = executable(0x400000);
        bytes[0x200 + 33] = 0;
        assert!(from_pe(&bytes, &AtomicBool::new(false)).unwrap().is_none());
    }

    #[test]
    fn equivalent_mov_encodings_preserve_initialization_dataflow() {
        let mut bytes = executable(0x400000);
        // MOV EAX,EDI: both opcode directions have the same operands.
        bytes[0x21a..0x21c].copy_from_slice(&[0x89, 0xf8]);
        // MOV [absolute],AL: generic ModRM instead of the accumulator form.
        let address = BinaryReader::u32_le(&bytes[0x243..]);
        bytes[0x242..0x244].copy_from_slice(&[0x88, 5]);
        BinaryWriter::u32_le(address, &mut bytes[0x244..]);
        assert_eq!(
            from_pe(&bytes, &AtomicBool::new(false))
                .unwrap()
                .unwrap()
                .bytes(),
            [0xcb, 0xf4, 0x39, 0x26]
        );
        assert!(matches!(
            from_pe(&bytes, &AtomicBool::new(true)),
            Err(Error::Cancelled)
        ));
        // A branch to the middle of a load is not the string-length loop.
        bytes[0x20f] = 7;
        assert!(from_pe(&bytes, &AtomicBool::new(false)).unwrap().is_none());
    }
}
