//! License-backed YSTB keys: sub_4678FC reads 28-byte YS_BIN/#148 records,
//! adding their two big-endian words at +20/+24 with u32 wraparound.
//! sub_469D99 serializes the result into the four-byte XOR key. Some clients
//! replace the license call with a MOV immediate into that same source slot
//! (sub_460C04). Both are selected by decoded stores and the four XOR loops,
//! without executing the client or requiring a registration identifier.

use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_core::{Error, Result, Secret};
use vnlens_io::{BinaryReader, BinaryWriter, pe::PeImage};

pub(super) fn from_image(pe: &PeImage<'_>, cancelled: &AtomicBool) -> Result<Option<Secret>> {
    if pe.machine != 0x14c {
        return Ok(None);
    }
    let mut serializers = Vec::new();
    let mut loops = BTreeMap::<u32, usize>::new();
    let mut constants = BTreeMap::<u32, Vec<u32>>::new();
    for section in pe.sections.iter().filter(|section| section.executable) {
        let code = pe.section_data(section)?;
        for start in 0..code.len() {
            if start.is_multiple_of(4096) && cancelled.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let mut decoder =
                Decoder::with_ip(32, &code[start..], start as u64, DecoderOptions::NONE);
            let first = decoder.decode();
            if first.mnemonic() == Mnemonic::Mov
                && first.op0_kind() == OpKind::Memory
                && absolute(&first)
                && first.op1_kind() == OpKind::Immediate32
            {
                constants
                    .entry(first.memory_displacement32())
                    .or_default()
                    .push(first.immediate32());
            }
            if !matches!(first.mnemonic(), Mnemonic::Mov | Mnemonic::Inc) {
                continue;
            }
            let mut p = [Instruction::default(); 11];
            p[0] = first;
            for instruction in &mut p[1..] {
                *instruction = decoder.decode();
            }
            if let Some(pair) = serialization(&p) {
                serializers.push(pair);
            }
            if let Some(address) = xor_loop(&p) {
                *loops.entry(address).or_default() += 1;
            }
        }
    }
    let mut found = None;
    for (source, destination) in serializers {
        if loops.get(&destination).copied().unwrap_or(0) < 4 {
            continue;
        }
        let word = if let Some(values) = constants.get(&source) {
            let mut word = None;
            for &value in values {
                merge(&mut word, value)?;
            }
            word
        } else if let Some(resource) = pe.resource("YS_BIN", "#148")? {
            let (records, trailing) = resource.as_chunks::<28>();
            if !trailing.is_empty() {
                return Err(Error::UnknownScheme(Some(
                    "Invalid YU-RIS license record layout".into(),
                )));
            }
            let mut word = None;
            for record in records {
                if cancelled.load(Ordering::Relaxed) {
                    return Err(Error::Cancelled);
                }
                merge(
                    &mut word,
                    BinaryReader::u32_be(&record[20..])
                        .wrapping_add(BinaryReader::u32_be(&record[24..])),
                )?;
            }
            word
        } else {
            None
        };
        if let Some(word) = word {
            merge(&mut found, word)?;
        }
    }
    Ok(found.map(|word| {
        let mut bytes = [0; 4];
        BinaryWriter::u32_be(word, &mut bytes);
        Secret::new(bytes)
    }))
}

fn merge(found: &mut Option<u32>, word: u32) -> Result<()> {
    if found.is_some_and(|previous| previous != word) {
        return Err(Error::UnknownScheme(Some(
            "Conflicting YU-RIS license keys".into(),
        )));
    }
    *found = Some(word);
    Ok(())
}

fn absolute(i: &Instruction) -> bool {
    i.memory_base() == Register::None && i.memory_index() == Register::None
}

fn unary(i: &Instruction, mnemonic: Mnemonic, register: Register) -> bool {
    i.mnemonic() == mnemonic && i.op0_kind() == OpKind::Register && i.op0_register() == register
}

fn pair(i: &Instruction, mnemonic: Mnemonic, dst: Register, src: Register) -> bool {
    unary(i, mnemonic, dst) && i.op1_kind() == OpKind::Register && i.op1_register() == src
}

fn low(register: Register) -> Option<Register> {
    use Register::*;
    match register {
        EAX => Some(AL),
        EBX => Some(BL),
        ECX => Some(CL),
        EDX => Some(DL),
        _ => Option::None,
    }
}

fn serialization(p: &[Instruction; 11]) -> Option<(u32, u32)> {
    use Mnemonic as M;
    let word = p[0].op0_register();
    if !unary(&p[0], M::Mov, word)
        || p[0].op1_kind() != OpKind::Memory
        || !absolute(&p[0])
        || p[0].memory_size() != MemorySize::UInt32
    {
        return None;
    }
    let destination = p[3].memory_displacement32();
    for (index, shift) in [24, 16, 8].into_iter().enumerate() {
        let at = 1 + index * 3;
        let register = p[at].op0_register();
        let byte = low(register)?;
        let store = &p[at + 2];
        if !pair(&p[at], M::Mov, register, word)
            || !unary(&p[at + 1], M::Shr, register)
            || p[at + 1].op1_kind() != OpKind::Immediate8
            || p[at + 1].immediate8() != shift
            || store.mnemonic() != M::Mov
            || store.op0_kind() != OpKind::Memory
            || !absolute(store)
            || store.op1_kind() != OpKind::Register
            || store.op1_register() != byte
            || store.memory_displacement32() != destination.checked_add(index as u32)?
        {
            return None;
        }
    }
    let store = &p[10];
    if store.mnemonic() != M::Mov
        || store.op0_kind() != OpKind::Memory
        || !absolute(store)
        || store.op1_kind() != OpKind::Register
        || store.op1_register() != low(word)?
        || store.memory_displacement32() != destination.checked_add(3)?
    {
        return None;
    }
    Some((p[0].memory_displacement32(), destination))
}

fn xor_loop(p: &[Instruction; 11]) -> Option<u32> {
    use Mnemonic as M;
    let pointer = p[0].op0_register();
    let index = p[1].op1_register();
    let masked = p[1].op0_register();
    let value = p[3].op0_register();
    if !unary(&p[0], M::Inc, pointer)
        || pointer.size() != 4
        || !pair(&p[1], M::Mov, masked, index)
        || !unary(&p[2], M::And, masked)
        || p[2].op1_kind() != OpKind::Immediate8to32
        || p[2].immediate8to32() != 3
        || !unary(&p[3], M::Movzx, value)
        || p[3].op1_kind() != OpKind::Memory
        || p[3].memory_size() != MemorySize::UInt8
        || p[3].memory_base() != masked
        || p[3].memory_index() != Register::None
        || p[4].mnemonic() != M::Xor
        || p[4].op0_kind() != OpKind::Memory
        || p[4].memory_base() != pointer
        || p[4].memory_index() != Register::None
        || p[4].memory_displacement32() != u32::MAX
        || p[4].op1_kind() != OpKind::Register
        || p[4].op1_register() != low(value)?
        || !unary(&p[5], M::Inc, index)
        || !unary(&p[6], M::Cmp, index)
        || p[6].op1_kind() != OpKind::Register
        || p[7].mnemonic() != M::Jl
        || p[7].near_branch_target() != p[0].ip()
    {
        return None;
    }
    Some(p[3].memory_displacement32())
}

#[cfg(test)]
#[path = "../../tests/yuris/license.rs"]
mod tests;
