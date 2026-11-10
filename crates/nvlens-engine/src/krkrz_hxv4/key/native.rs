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
#[path = "../../../tests/krkrz_hxv4/key/native.rs"]
mod tests;
