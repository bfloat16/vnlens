//! Static x86 Siglus loader analysis, verified in sub_68EA00/sub_6984D0 and
//! sub_6A2360/sub_6ACDD0 and sub_69F460/sub_6AA490. Scattered bytes form a
//! 16-byte stack key; actual XOR
//! loops bind it to a 256-byte table. Scene header fields +0x54/+0x58 identify
//! its optional key and compression; Gameexe's +4 guard identifies its key.
//! Instruction operands, loop targets and field offsets determine the role,
//! independently of register allocation, stack displacement or image base.
use crate::context::Context;
use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};
use nvlens_core::{ArchiveOptions, Error, Result, Secret};
use nvlens_io::pe::PeImage;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

fn missing() -> Error {
    Error::UnknownScheme(Some(
        "Siglus resource-key code features were not resolved".into(),
    ))
}

pub(super) fn resolve(
    context: &Context,
    executables: &[PathBuf],
    cancelled: &AtomicBool,
) -> Result<ArchiveOptions> {
    let mut result = None;
    for executable in executables {
        check(cancelled)?;
        let view = context.files.open(executable)?;
        let Some(image) = context.image(&view, cancelled)? else {
            continue;
        };
        if !super::pe(&image)? {
            continue;
        }
        let options = parameters(&image, cancelled)?;
        if result.as_ref().is_some_and(|previous| previous != &options) {
            return Err(Error::UnknownScheme(Some(
                "Conflicting Siglus executable parameters".into(),
            )));
        }
        result = Some(options);
    }
    result.ok_or_else(missing)
}

fn parameters(image: &PeImage<'_>, cancel: &AtomicBool) -> Result<ArchiveOptions> {
    if image.machine != 0x14c {
        return Err(missing());
    }
    let mut options = ArchiveOptions::default();
    for section in image.sections.iter().filter(|s| s.executable) {
        let code = image.section_data(section)?;
        for start in 0..code.len() {
            if start.is_multiple_of(4096) {
                check(cancel)?;
            }
            let Some(array) = key_array(image, code, start) else {
                continue;
            };
            let Some((name, address)) = loader(code, start, &array, cancel)? else {
                continue;
            };
            let Some(table) = image.at_va(address).and_then(|b| b.get(..256)) else {
                continue;
            };
            for (name, bytes) in [("siglus_game", array.bytes.as_slice()), (name, table)] {
                let value = Secret::new(bytes);
                if options.keys.get(name).is_some_and(|old| old != &value) {
                    return Err(Error::UnknownScheme(Some(format!(
                        "Conflicting Siglus {name} construction features"
                    ))));
                }
                options.keys.insert(name, value);
            }
        }
    }
    if ["siglus_game", "siglus_scene", "siglus_gameexe"]
        .iter()
        .any(|k| !options.keys.contains_key(k))
    {
        return Err(missing());
    }
    Ok(options)
}
fn check(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
struct KeyArray {
    end: usize,
    stack: u32,
    bytes: [u8; 16],
}
fn key_array(image: &PeImage<'_>, code: &[u8], start: usize) -> Option<KeyArray> {
    let mut decoder = Decoder::with_ip(32, code.get(start..)?, start as u64, DecoderOptions::NONE);
    let mut slots = [(0i32, 0u8); 16];
    for (index, slot) in slots.iter_mut().enumerate() {
        let mut load = decoder.decode();
        // Keep the candidate anchored at its first byte load so the preceding
        // Gameexe guard is checked at the actual start of key construction.
        if index != 0 {
            while key_setup(&load) {
                load = decoder.decode();
            }
        }
        if load.mnemonic() != Mnemonic::Mov
            || load.op0_register() != Register::AL
            || load.op1_kind() != OpKind::Memory
            || load.memory_size() != MemorySize::UInt8
            || load.memory_base() != Register::None
            || load.memory_index() != Register::None
        {
            return None;
        }
        let byte = *image
            .at_va(u64::from(load.memory_displacement32()))?
            .first()?;
        let mut store = decoder.decode();
        while key_setup(&store) {
            store = decoder.decode();
        }
        if store.mnemonic() != Mnemonic::Mov
            || store.op0_kind() != OpKind::Memory
            || store.op1_kind() != OpKind::Register
            || store.op1_register() != load.op0_register()
            || store.memory_size() != MemorySize::UInt8
            || store.memory_base() != Register::EBP
            || store.memory_index() != Register::None
        {
            return None;
        }
        *slot = (store.memory_displacement32() as i32, byte);
    }
    slots.sort_by_key(|&(slot, _)| slot);
    let mut bytes = [0; 16];
    for (i, &(slot, byte)) in slots.iter().enumerate() {
        if slot != slots[0].0.checked_add(i as i32)? {
            return None;
        }
        bytes[i] = byte;
    }
    Some(KeyArray {
        end: usize::try_from(decoder.ip()).ok()?,
        stack: slots[0].0 as u32,
        bytes,
    })
}

// The loaders schedule counter/pointer initialization both inside a byte
// copy and between copies. Only register assignments that preserve AL, EBP,
// ESP and every stored key byte may be skipped. Calls, jumps and memory writes
// must still terminate a candidate rather than binding unrelated byte loads.
fn key_setup(instruction: &Instruction) -> bool {
    let destination = instruction.op0_register();
    if instruction.op0_kind() != OpKind::Register
        || !destination.is_gpr32()
        || matches!(destination, Register::EAX | Register::EBP | Register::ESP)
    {
        return false;
    }
    match instruction.mnemonic() {
        Mnemonic::Xor => {
            instruction.op1_kind() == OpKind::Register && instruction.op1_register() == destination
        }
        Mnemonic::Mov => match instruction.op1_kind() {
            OpKind::Register => instruction.op1_register().is_gpr32(),
            OpKind::Memory => {
                instruction.memory_size() == MemorySize::UInt32
                    && instruction.memory_base() == Register::EBP
                    && instruction.memory_index() == Register::None
            }
            _ => false,
        },
        _ => false,
    }
}

fn loader(
    code: &[u8],
    start: usize,
    array: &KeyArray,
    cancel: &AtomicBool,
) -> Result<Option<(&'static str, u64)>> {
    let mut decoder = Decoder::with_ip(
        32,
        &code[array.end..],
        array.end as u64,
        DecoderOptions::NONE,
    );
    let mut instructions = Vec::new();
    let mut used_key = false;
    while decoder.can_decode() {
        check(cancel)?;
        let instruction = decoder.decode();
        if matches!(
            instruction.mnemonic(),
            Mnemonic::INVALID | Mnemonic::Ret | Mnemonic::Retf | Mnemonic::Int3
        ) {
            break;
        }
        if instruction.mnemonic() == Mnemonic::Jmp && !alignment_jump(code, &instruction) {
            break;
        }
        instructions.push(instruction);
        let Some(loop_code) = instructions
            .len()
            .checked_sub(11)
            .map(|i| &instructions[i..])
        else {
            continue;
        };
        if let Some(index) = xor_loop(loop_code, 15) {
            let load = &loop_code[0];
            used_key |= load.memory_base() == Register::EBP
                && load.memory_index() == index
                && load.memory_index_scale() == 1
                && load.memory_displacement32() == array.stack;
        }
        let Some(index) = xor_loop(loop_code, 255) else {
            continue;
        };
        let load = &loop_code[0];
        if !used_key
            || !((load.memory_base() == index && load.memory_index() == Register::None)
                || (load.memory_base() == Register::None
                    && load.memory_index() == index
                    && load.memory_index_scale() == 1))
        {
            continue;
        }
        // Both fields must refer to the same header base. A missing scene
        // pattern is never by itself evidence for the Gameexe table.
        let scene = instructions
            .iter()
            .filter(|i| compare_field(i, 0x58))
            .any(|compressed| {
                instructions
                    .iter()
                    .any(|i| compare_field(i, 0x54) && i.memory_base() == compressed.memory_base())
            });
        let gameexe = gameexe_guard(code, start, loop_code[0].ip());
        let name = match (scene, gameexe) {
            (true, false) => "siglus_scene",
            (false, true) => "siglus_gameexe",
            _ => return Ok(None),
        };
        return Ok(Some((name, u64::from(load.memory_displacement32()))));
    }
    Ok(None)
}
fn alignment_jump(code: &[u8], jump: &Instruction) -> bool {
    if jump.op0_kind() != OpKind::NearBranch32 {
        return false;
    }
    let (Ok(start), Ok(end)) = (
        usize::try_from(jump.next_ip()),
        usize::try_from(jump.near_branch_target()),
    ) else {
        return false;
    };
    let Some(padding) = code.get(start..end) else {
        return false;
    };
    let mut decoder = Decoder::new(32, padding, DecoderOptions::NONE);
    while decoder.can_decode() {
        let i = decoder.decode();
        if i.mnemonic() != Mnemonic::Nop
            && !(i.mnemonic() == Mnemonic::Lea
                && i.op0_kind() == OpKind::Register
                && i.op1_kind() == OpKind::Memory
                && i.op0_register() == i.memory_base()
                && i.memory_index() == Register::None
                && i.memory_displacement32() == 0)
        {
            return false;
        }
    }
    true
}
fn compare_field(i: &Instruction, offset: u32) -> bool {
    i.mnemonic() == Mnemonic::Cmp
        && i.op0_kind() == OpKind::Memory
        && i.memory_size() == MemorySize::UInt32
        && i.memory_base() != Register::None
        && i.memory_index() == Register::None
        && i.memory_displacement32() == offset
        && immediate(i) == Some(0)
}
fn gameexe_guard(code: &[u8], start: usize, table: u64) -> bool {
    // x86 instructions are at most 15 bytes. Test the immediately preceding
    // CMP/JE pair, not an arbitrary byte window inside another instruction.
    for branch_len in [2, 6] {
        let Some(branch_at) = start.checked_sub(branch_len) else {
            continue;
        };
        let mut d = Decoder::with_ip(
            32,
            &code[branch_at..start],
            branch_at as u64,
            DecoderOptions::NONE,
        );
        let jump = d.decode();
        if jump.mnemonic() != Mnemonic::Je
            || jump.next_ip() != start as u64
            || jump.near_branch_target() < start as u64
            || jump.near_branch_target() > table
        {
            continue;
        }
        for length in 1..=15 {
            let Some(at) = branch_at.checked_sub(length) else {
                continue;
            };
            let mut d = Decoder::with_ip(32, &code[at..branch_at], at as u64, DecoderOptions::NONE);
            let cmp = d.decode();
            if cmp.next_ip() == branch_at as u64 && compare_field(&cmp, 4) {
                return true;
            }
        }
    }
    false
}
fn immediate(i: &Instruction) -> Option<u32> {
    match i.op1_kind() {
        OpKind::Immediate8 => Some(u32::from(i.immediate8())),
        OpKind::Immediate8to32 => Some(i.immediate8to32() as u32),
        OpKind::Immediate32 => Some(i.immediate32()),
        _ => None,
    }
}
fn register_op(i: &Instruction, mnemonic: Mnemonic, register: Register) -> bool {
    i.mnemonic() == mnemonic && i.op0_kind() == OpKind::Register && i.op0_register() == register
}
fn decrement(i: &Instruction, register: Register) -> bool {
    register_op(i, Mnemonic::Dec, register)
        || register_op(i, Mnemonic::Sub, register) && immediate(i) == Some(1)
}

/// Recognizes the decoded signed-modulo XOR loop. The branch targets prove
/// which instructions belong to it; immediates containing opcode bytes cannot
/// become false RETs, field tests or another loader's table references.
fn xor_loop(p: &[Instruction], mask: u32) -> Option<Register> {
    let index = p[3].op0_register();
    let pointer = p[1].op0_register();
    if index == Register::None
        || pointer == Register::None
        || index == pointer
        || p[0].mnemonic() != Mnemonic::Mov
        || p[0].op0_register() != Register::AL
        || p[0].op1_kind() != OpKind::Memory
        || p[0].memory_size() != MemorySize::UInt8
        || p[1].mnemonic() != Mnemonic::Lea
        || p[1].op1_kind() != OpKind::Memory
        || p[1].memory_base() != pointer
        || p[1].memory_index() != Register::None
        || p[1].memory_displacement32() != 1
        || p[2].mnemonic() != Mnemonic::Xor
        || p[2].op0_kind() != OpKind::Memory
        || p[2].memory_base() != pointer
        || p[2].memory_index() != Register::None
        || p[2].memory_displacement32() != u32::MAX
        || p[2].op1_register() != Register::AL
        || !register_op(&p[3], Mnemonic::Inc, index)
        || !register_op(&p[4], Mnemonic::And, index)
        || immediate(&p[4]) != Some(0x8000_0000 | mask)
        || p[5].mnemonic() != Mnemonic::Jns
        || p[5].near_branch_target() != p[9].ip()
        || !register_op(&p[6], Mnemonic::Dec, index)
        || !register_op(&p[7], Mnemonic::Or, index)
        || immediate(&p[7]) != Some(!mask)
        || !register_op(&p[8], Mnemonic::Inc, index)
        || !decrement(&p[9], p[9].op0_register())
        || p[10].mnemonic() != Mnemonic::Jne
        || p[10].near_branch_target() != p[0].ip()
    {
        return None;
    }
    Some(index)
}

#[cfg(test)]
#[path = "../../tests/siglus/key.rs"]
mod tests;
