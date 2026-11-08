//! Native BasicCryptoFilter salt assignment and Hxv4 KDF seed arguments.
//! Match decoded memory/register/immediate operands and control flow, without
//! byte-pattern searches or offsets tied to a particular instruction encoding.
use super::check;
use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};
use nvlens_core::Result;
use nvlens_io::{BinaryWriter, pe::PeImage};
use std::sync::atomic::AtomicBool;

pub(super) fn salts<'a>(image: &'a PeImage<'_>, cancel: &AtomicBool) -> Result<Vec<&'a [u8]>> {
    let mut found = Vec::new();
    if image.machine != 0x14c {
        return Ok(found);
    }
    for section in image.sections.iter().filter(|s| s.executable) {
        let code = image.section_data(section)?;
        for start in 0..code.len() {
            if start.is_multiple_of(4096) {
                check(cancel)?;
            }
            let mut d = Decoder::with_ip(32, &code[start..], start as u64, DecoderOptions::NONE);
            let compare = d.decode();
            if compare.mnemonic() != Mnemonic::Cmp
                || compare.op0_kind() != OpKind::Memory
                || !absolute(&compare)
                || compare.memory_size() != MemorySize::UInt32
                || immediate(&compare) != Some(0)
            {
                continue;
            }
            let branch = d.decode();
            let pointer = d.decode();
            let length = d.decode();
            if branch.mnemonic() != Mnemonic::Jbe
                || branch.near_branch_target() < length.next_ip()
                || !constant_store(&pointer)
                || !absolute(&pointer)
                || !constant_store(&length)
                || !absolute(&length)
                || pointer.memory_displacement32() == length.memory_displacement32()
                || immediate(&length) != Some(0x2000)
            {
                continue;
            }
            if let Some(address) = immediate(&pointer)
                && let Some(salt) = image
                    .at_va(u64::from(address))
                    .and_then(|b| b.get(..0x2000))
            {
                found.push(salt);
            }
        }
    }
    found.sort();
    found.dedup();
    Ok(found)
}

pub(super) fn seeds(image: &PeImage<'_>, cancel: &AtomicBool) -> Result<Vec<[u8; 8]>> {
    let mut found = Vec::new();
    if image.machine != 0x14c {
        return Ok(found);
    }
    for section in image.sections.iter().filter(|s| s.executable) {
        let code = image.section_data(section)?;
        for start in 0..code.len() {
            if start.is_multiple_of(4096) {
                check(cancel)?;
            }
            let mut d = Decoder::with_ip(32, &code[start..], start as u64, DecoderOptions::NONE);
            let low = d.decode();
            if !constant_store(&low)
                || low.memory_base() != Register::EBP
                || low.memory_index() != Register::None
            {
                continue;
            }
            let high = d.decode();
            if !constant_store(&high)
                || high.memory_base() != low.memory_base()
                || high.memory_index() != Register::None
                || low.memory_displacement32().checked_add(4) != Some(high.memory_displacement32())
            {
                continue;
            }
            let select = d.decode();
            if select.mnemonic() != Mnemonic::Cmovne
                || select.op0_kind() != OpKind::Register
                || select.op1_kind() != OpKind::Register
            {
                continue;
            }
            let register = select.op0_register();
            let mut pointer = false;
            let mut size = false;
            let mut word = false;
            let mut setup_call = None;
            while d.can_decode() {
                check(cancel)?;
                let i = d.decode();
                match i.mnemonic() {
                    Mnemonic::Push => match i.op0_kind() {
                        OpKind::Register if i.op0_register() == register => pointer = true,
                        OpKind::Immediate8to32 if i.immediate8to32() == 8 => size = true,
                        OpKind::Immediate32 if i.immediate32() == 8 => size = true,
                        OpKind::Memory
                            if i.memory_base() == register
                                && i.memory_index() == Register::None
                                && i.memory_displacement32() == 0
                                && i.memory_size() == MemorySize::UInt32 =>
                        {
                            word = true
                        }
                        _ => {}
                    },
                    Mnemonic::Call => {
                        if !pointer
                            && !size
                            && !word
                            && setup_call.is_none()
                            && i.op0_kind() == OpKind::NearBranch32
                            && matches!(
                                register,
                                Register::EBX | Register::ESI | Register::EDI | Register::EBP
                            )
                        {
                            // The first KDF call uses the primary password;
                            // the selected seed stays in a callee-saved register.
                            setup_call = Some(i.near_branch_target());
                            continue;
                        }
                        if pointer
                            && size
                            && word
                            && i.op0_kind() == OpKind::NearBranch32
                            && setup_call.is_none_or(|target| target == i.near_branch_target())
                        {
                            let mut seed = [0; 8];
                            BinaryWriter::u32_le(low.immediate32(), &mut seed);
                            BinaryWriter::u32_le(high.immediate32(), &mut seed[4..]);
                            found.push(seed);
                        }
                        break;
                    }
                    Mnemonic::Mov | Mnemonic::Lea | Mnemonic::Xor
                        if i.op0_register() == register =>
                    {
                        break;
                    }
                    Mnemonic::INVALID
                    | Mnemonic::Ret
                    | Mnemonic::Retf
                    | Mnemonic::Int3
                    | Mnemonic::Jmp => break,
                    _ => {}
                }
            }
        }
    }
    Ok(found)
}
fn absolute(i: &Instruction) -> bool {
    i.memory_base() == Register::None && i.memory_index() == Register::None
}
fn constant_store(i: &Instruction) -> bool {
    i.mnemonic() == Mnemonic::Mov
        && i.op0_kind() == OpKind::Memory
        && i.memory_size() == MemorySize::UInt32
        && i.op1_kind() == OpKind::Immediate32
}
fn immediate(i: &Instruction) -> Option<u32> {
    match i.op1_kind() {
        OpKind::Immediate8to32 => Some(i.immediate8to32() as u32),
        OpKind::Immediate32 => Some(i.immediate32()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nvlens_core::Error;
    fn word(out: &mut Vec<u8>, value: u32) {
        let at = out.len();
        out.resize(at + 4, 0);
        BinaryWriter::u32_le(value, &mut out[at..]);
    }
    fn call(out: &mut Vec<u8>, target: u32) {
        out.push(0xe8);
        word(out, target.wrapping_sub(out.len() as u32 + 4));
    }
    fn fixture(base: u32, alternate: bool) -> Vec<u8> {
        let mut bytes = vec![0; 0x2600];
        bytes[..2].copy_from_slice(b"MZ");
        BinaryWriter::u32_le(0x80, &mut bytes[0x3c..]);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        for (at, n) in [(0x84, 0x14c), (0x86, 1), (0x94, 0xe0), (0x98, 0x10b)] {
            BinaryWriter::u16_le(n, &mut bytes[at..]);
        }
        for (at, n) in [
            (0xb4, base),
            (0xd4, 0x200),
            (0x184, 0x1000),
            (0x188, 0x2400),
            (0x18c, 0x200),
            (0x19c, 0x20000000),
        ] {
            BinaryWriter::u32_le(n, &mut bytes[at..]);
        }
        let mut code = Vec::new();
        code.extend([if alternate { 0x81 } else { 0x83 }, 0x3d]);
        word(&mut code, base + 0x1300);
        if alternate {
            word(&mut code, 0);
            code.extend([0x76, 20]);
        } else {
            code.push(0);
            code.extend([0x0f, 0x86]);
            word(&mut code, 20);
        }
        for (slot, value) in [(base + 0x1310, base + 0x1400), (base + 0x1314, 0x2000)] {
            code.extend([0xc7, 5]);
            word(&mut code, slot);
            word(&mut code, value);
        }
        code.push(0xc3);
        bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
        let mut code = Vec::new();
        for (offset, value) in [(0, 0x12345678), (4, 0x9abcdef0)] {
            code.extend([0xc7, if alternate { 0x85 } else { 0x45 }]);
            if alternate {
                word(&mut code, (-0x120i32 + offset) as u32);
            } else {
                code.push((0xe0 + offset) as u8);
            }
            word(&mut code, value);
        }
        let reg = if alternate { 7 } else { 6 };
        code.extend([0x0f, 0x45, 0xc0 | (reg * 8)]);
        call(&mut code, 0x500);
        code.extend([0xff, 0x30 | reg]);
        if alternate {
            code.push(0x68);
            word(&mut code, 8);
        } else {
            code.extend([0x6a, 8]);
        }
        code.push(0x50 | reg);
        call(&mut code, 0x500);
        code.push(0xc3);
        bytes[0x300..0x300 + code.len()].copy_from_slice(&code);
        bytes[0x600..].fill(0x5a);
        bytes
    }
    #[test]
    fn reads_relocated_salt_and_seed_with_equivalent_encodings() -> Result<()> {
        for base in [0x400000, 0x710000] {
            for alternate in [false, true] {
                let bytes = fixture(base, alternate);
                let pe = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
                let cancel = AtomicBool::new(false);
                assert_eq!(salts(&pe, &cancel)?, vec![&bytes[0x600..]]);
                assert_eq!(
                    seeds(&pe, &cancel)?,
                    [[0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x9a]]
                );
                assert!(matches!(
                    salts(&pe, &AtomicBool::new(true)),
                    Err(Error::Cancelled)
                ));
                assert!(matches!(
                    seeds(&pe, &AtomicBool::new(true)),
                    Err(Error::Cancelled)
                ));
            }
        }
        Ok(())
    }
    #[test]
    fn rejects_unrelated_arguments_and_inconsistent_kdf_calls() -> Result<()> {
        for change in [0, 1, 2] {
            let mut bytes = fixture(0x400000, false);
            let instructions = Decoder::new(32, &bytes[0x300..0x400], DecoderOptions::NONE)
                .into_iter()
                .collect::<Vec<_>>();
            if change == 0 {
                let push = instructions
                    .iter()
                    .find(|i| {
                        i.mnemonic() == Mnemonic::Push && i.op0_kind() == OpKind::Immediate8to32
                    })
                    .ok_or(Error::InvalidFormat)?;
                bytes[0x300 + push.next_ip() as usize - 1] = 9;
            } else {
                let call = instructions
                    .iter()
                    .filter(|i| i.mnemonic() == Mnemonic::Call)
                    .nth(1)
                    .ok_or(Error::InvalidFormat)?;
                if change == 1 {
                    bytes[0x300 + call.ip() as usize + 1] ^= 1;
                } else {
                    bytes[0x300 + call.ip() as usize] = 0xc3;
                }
            }
            let pe = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
            assert!(seeds(&pe, &AtomicBool::new(false))?.is_empty());
        }
        Ok(())
    }
}
