//! YPF filename decoding at client 0x45EC64 (complement) and 0x464314
//! (complement followed by XOR). Recognize both loops and the decoded buffer
//! passed to the comparison with `ysbin\\yscfg.ybn`, using x86 dataflow.

use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{Error, Result, Secret};
use vnlens_io::pe::PeImage;

pub(super) fn from_image(pe: &PeImage<'_>, cancel: &AtomicBool) -> Result<Option<Secret>> {
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
            if first.mnemonic() != Mnemonic::Movsx || first.op1_kind() != OpKind::Memory {
                continue;
            }
            let mut instructions = [Instruction::default(); 18];
            instructions[0] = first;
            for instruction in &mut instructions[1..] {
                *instruction = decoder.decode();
            }
            if let Some(byte) = name_key(&instructions, pe) {
                let key = Secret::new([byte]);
                if found.as_ref().is_some_and(|previous| previous != &key) {
                    return Err(Error::UnknownScheme(Some(
                        "Conflicting YU-RIS filename keys".into(),
                    )));
                }
                found = Some(key);
            }
        }
    }
    Ok(found)
}

fn same_buffer(a: &Instruction, b: &Instruction) -> bool {
    a.memory_base() == b.memory_base()
        && a.memory_index() == b.memory_index()
        && a.memory_index_scale() == b.memory_index_scale()
        && a.memory_displacement32() == b.memory_displacement32()
}

fn unary(i: &Instruction, mnemonic: Mnemonic, register: Register) -> bool {
    i.mnemonic() == mnemonic && i.op0_kind() == OpKind::Register && i.op0_register() == register
}

fn pair(i: &Instruction, mnemonic: Mnemonic, a: Register, b: Register) -> bool {
    unary(i, mnemonic, a) && i.op1_kind() == OpKind::Register && i.op1_register() == b
}

fn name_key(p: &[Instruction; 18], pe: &PeImage<'_>) -> Option<u8> {
    use Mnemonic as M;
    use Register as R;
    let buffer = &p[0];
    let index = buffer.memory_index();
    let count = p[5].op1_register();
    if buffer.op0_register() != R::EAX
        || buffer.memory_size() != MemorySize::Int8
        || buffer.memory_base() != R::ESP
        || index == R::None
        || buffer.memory_index_scale() != 1
        || !unary(&p[1], M::Neg, R::EAX)
        || !unary(&p[2], M::Dec, R::EAX)
        || p[3].mnemonic() != M::Mov
        || p[3].op0_kind() != OpKind::Memory
        || p[3].op1_kind() != OpKind::Register
        || p[3].op1_register() != R::AL
        || !same_buffer(buffer, &p[3])
        || !unary(&p[4], M::Inc, index)
        || !pair(&p[5], M::Cmp, index, count)
        || p[6].mnemonic() != M::Jl
        || p[6].near_branch_target() != p[0].ip()
    {
        return None;
    }
    let mut key = 0xff;
    let mut tail = 7;
    if p[7].mnemonic() == M::Test {
        let xor_index = p[10].memory_index();
        if !pair(&p[7], M::Test, count, count)
            || p[8].mnemonic() != M::Jle
            || p[8].near_branch_target() != p[14].ip()
            || xor_index == R::None
            || !pair(&p[9], M::Xor, xor_index, xor_index)
            || p[10].mnemonic() != M::Xor
            || p[10].op0_kind() != OpKind::Memory
            || p[10].memory_size() != MemorySize::UInt8
            || p[10].memory_base() != buffer.memory_base()
            || p[10].memory_displacement32() != buffer.memory_displacement32()
            || p[10].memory_index_scale() != 1
            || p[10].op1_kind() != OpKind::Immediate8
            || !unary(&p[11], M::Inc, xor_index)
            || !pair(&p[12], M::Cmp, xor_index, count)
            || p[13].mnemonic() != M::Jl
            || p[13].near_branch_target() != p[10].ip()
        {
            return None;
        }
        key ^= p[10].immediate8();
        tail = 14;
    }
    let address = &p[tail];
    let push = &p[tail + 2];
    if address.mnemonic() != M::Lea
        || address.op0_kind() != OpKind::Register
        || address.op1_kind() != OpKind::Memory
        || address.memory_base() != buffer.memory_base()
        || address.memory_index() != R::None
        || address.memory_displacement32() != buffer.memory_displacement32()
        || !unary(&p[tail + 1], M::Push, address.op0_register())
        || push.mnemonic() != M::Push
        || push.op0_kind() != OpKind::Immediate32
        || pe.c_string_at_va(u64::from(push.immediate32())) != Some(b"ysbin\\yscfg.ybn")
        || p[tail + 3].mnemonic() != M::Call
        || p[tail + 3].op0_kind() != OpKind::NearBranch32
    {
        return None;
    }
    Some(key)
}

#[cfg(test)]
#[path = "../../tests/yuris/name.rs"]
mod tests;
