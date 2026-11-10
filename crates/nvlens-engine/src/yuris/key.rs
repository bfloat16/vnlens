//! Relocated x86 YU-RIS product string, CRC32 call and big-endian key stores.
//! Decode instructions and verify the string-length loop and output dataflow;
//! no executable opcode bytes or fixed image addresses are matched.
use crate::context::Context;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use nvlens_core::{ArchiveOptions, Error, Result, Secret};
use nvlens_crypto::checksum::crc32;
use nvlens_io::{BinaryReader, BinaryWriter, pe::PeImage};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

pub(super) fn resolve(
    context: &Context,
    executables: &[PathBuf],
    cancelled: &AtomicBool,
) -> Result<ArchiveOptions> {
    let mut found = None;
    for path in executables {
        if cancelled.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let view = context.files.open(path)?;
        if let Some(image) = context.image(&view, cancelled)?
            && let Some(key) = from_image(&image, cancelled)?
        {
            if found.as_ref().is_some_and(|previous| previous != &key) {
                return Err(Error::UnknownScheme(Some("Conflicting YU-RIS keys".into())));
            }
            found = Some(key);
        }
    }
    let key = found.ok_or_else(|| {
        Error::UnknownScheme(Some(
            "YU-RIS executable key initialization was not identified".into(),
        ))
    })?;
    let mut options = ArchiveOptions::default();
    options.keys.insert("ystb", key);
    // 0x45EC64 complements filename bytes; this is the verified 0x1EE profile.
    options.keys.insert("ypf_name", Secret::new(vec![0xff]));
    options.numbers.insert("version", 0x1ee);
    Ok(options)
}

fn from_image(pe: &PeImage<'_>, cancel: &AtomicBool) -> Result<Option<Secret>> {
    if pe.machine != 0x14c {
        return Ok(None);
    }
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
#[path = "../../tests/yuris/key.rs"]
mod tests;
