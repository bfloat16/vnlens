//! LoadAndDecryptSeen binds a 256-byte XOR table to a counted byte loop.
//! Its guarded [0x100,0x200] loop dereferences a global pointer twice to
//! obtain a 16-byte key assembled from scattered data-byte assignments.
//! Addresses and register dataflow are decoded with iced-x86; no code is run.
use crate::context::Context;
use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_core::{ArchiveOptions, Error, Result, Secret};
use vnlens_io::pe::PeImage;

fn missing(reason: &str) -> Error {
    Error::UnknownScheme(Some(format!("RealLive: {reason}")))
}
fn check(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

pub(super) fn resolve(
    context: &Context,
    executables: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<ArchiveOptions> {
    let mut found = None;
    for path in executables {
        check(cancel)?;
        let view = context.files.open(path)?;
        let Some(image) = context.image(&view, cancel)? else {
            continue;
        };
        if !super::pe(&image)? {
            continue;
        }
        let options = parameters(&image, cancel)?;
        if found.as_ref().is_some_and(|old| old != &options) {
            return Err(missing("Conflicting executable parameters"));
        }
        found = Some(options);
    }
    found.ok_or_else(|| missing("Executable resource parameters are unavailable"))
}

fn absolute(i: &Instruction) -> bool {
    i.memory_base() == Register::None && i.memory_index() == Register::None
}
fn immediate(i: &Instruction) -> Option<u32> {
    match i.op1_kind() {
        OpKind::Immediate32 => Some(i.immediate32()),
        OpKind::Immediate8to32 => Some(i.immediate8to32() as u32),
        _ => None,
    }
}

fn parameters(image: &PeImage<'_>, cancel: &AtomicBool) -> Result<ArchiveOptions> {
    if image.machine != 0x14c {
        return Err(missing("Unsupported executable machine"));
    }
    let mut tables = BTreeSet::new();
    let mut slots = BTreeSet::new();
    for section in image.sections.iter().filter(|s| s.executable) {
        let code = image.section_data(section)?;
        for start in 0..code.len() {
            if start.is_multiple_of(4096) {
                check(cancel)?;
            }
            let mut d = Decoder::with_ip(32, &code[start..], start as u64, DecoderOptions::NONE);
            let first = d.decode();
            if first.mnemonic() == Mnemonic::And && immediate(&first) == Some(255) {
                let load = d.decode();
                let xor = d.decode();
                if matches!(load.mnemonic(), Mnemonic::Mov | Mnemonic::Movzx)
                    && load.op0_kind() == OpKind::Register
                    && load.op1_kind() == OpKind::Memory
                    && load.memory_size() == MemorySize::UInt8
                    && load.memory_base() == first.op0_register()
                    && load.memory_index() == Register::None
                    && xor.mnemonic() == Mnemonic::Xor
                    && xor.op0_kind() == OpKind::Memory
                    && xor.op1_kind() == OpKind::Register
                    && xor.op1_register().full_register32() == load.op0_register().full_register32()
                {
                    let a = d.decode();
                    let b = d.decode();
                    let cmp = d.decode();
                    let branch = d.decode();
                    if (a.mnemonic() == Mnemonic::Inc
                        || (a.mnemonic() == Mnemonic::Add && immediate(&a) == Some(1)))
                        && (b.mnemonic() == Mnemonic::Inc
                            || (b.mnemonic() == Mnemonic::Add && immediate(&b) == Some(1)))
                        && cmp.mnemonic() == Mnemonic::Cmp
                        && branch.mnemonic() == Mnemonic::Jl
                        && branch.near_branch_target() <= first.ip()
                        && let Some(table) = image
                            .at_va(u64::from(load.memory_displacement32()))
                            .and_then(|b| b.get(..256))
                    {
                        tables.insert(table.to_vec());
                    }
                }
            } else if first.mnemonic() == Mnemonic::Lea
                && first.memory_displacement32() == (-0x100i32) as u32
            {
                let cmp = d.decode();
                let branch = d.decode();
                if cmp.mnemonic() != Mnemonic::Cmp
                    || cmp.op0_register() != first.op0_register()
                    || immediate(&cmp) != Some(0x100)
                    || branch.mnemonic() != Mnemonic::Ja
                    || branch.near_branch_target() <= branch.next_ip()
                {
                    continue;
                }
                let mut masked = false;
                while d.can_decode() && d.ip() < branch.near_branch_target() {
                    check(cancel)?;
                    let i = d.decode();
                    if i.mnemonic() == Mnemonic::And && immediate(&i) == Some(0x8000000f) {
                        masked = true;
                    }
                    if masked
                        && i.mnemonic() == Mnemonic::Mov
                        && i.op0_kind() == OpKind::Register
                        && i.op1_kind() == OpKind::Memory
                        && absolute(&i)
                    {
                        let next = d.decode();
                        if next.mnemonic() == Mnemonic::Mov
                            && next.op0_register() == i.op0_register()
                            && next.op1_kind() == OpKind::Memory
                            && next.memory_base() == i.op0_register()
                            && next.memory_index() == Register::None
                            && next.memory_displacement32() == 0
                        {
                            slots.insert(u64::from(i.memory_displacement32()));
                        }
                    }
                }
            }
        }
    }
    let Some(table) = tables.iter().next().filter(|_| tables.len() == 1) else {
        return Err(missing("Seen XOR table is missing or ambiguous"));
    };
    let mut options = ArchiveOptions::default();
    options
        .keys
        .insert("reallive_xor", Secret::new(table.as_slice()));
    let mut keys = BTreeSet::new();
    for slot in slots {
        keys.insert(constructed_key(image, slot, cancel)?);
    }
    if let Some(key) = keys.iter().next().filter(|_| keys.len() == 1) {
        options.keys.insert("reallive_key1", Secret::new(key));
    } else if !keys.is_empty() {
        return Err(missing("Seen secondary key is ambiguous"));
    }
    Ok(options)
}

#[derive(Clone, Copy)]
enum Cell {
    Unknown,
    Slot,
    Pointer,
    Byte(u8),
}
fn reg(r: Register) -> Option<usize> {
    match r.full_register32() {
        Register::EAX => Some(0),
        Register::ECX => Some(1),
        Register::EDX => Some(2),
        Register::EBX => Some(3),
        Register::ESP => Some(4),
        Register::EBP => Some(5),
        Register::ESI => Some(6),
        Register::EDI => Some(7),
        _ => None,
    }
}
fn constructed_key(image: &PeImage<'_>, slot: u64, cancel: &AtomicBool) -> Result<[u8; 16]> {
    let mut key = [None; 16];
    for section in image.sections.iter().filter(|s| s.executable) {
        let code = image.section_data(section)?;
        for start in 0..code.len() {
            if start.is_multiple_of(4096) {
                check(cancel)?;
            }
            let mut d = Decoder::new(32, &code[start..], DecoderOptions::NONE);
            let first = d.decode();
            if first.mnemonic() != Mnemonic::Mov
                || first.op0_kind() != OpKind::Register
                || first.op1_kind() != OpKind::Memory
                || !absolute(&first)
                || u64::from(first.memory_displacement32()) != slot
            {
                continue;
            }
            let mut registers = [Cell::Unknown; 8];
            let Some(first_register) = reg(first.op0_register()) else {
                continue;
            };
            registers[first_register] = Cell::Slot;
            while d.can_decode() {
                let i = d.decode();
                check(cancel)?;
                if matches!(
                    i.mnemonic(),
                    Mnemonic::Call
                        | Mnemonic::Ret
                        | Mnemonic::Jmp
                        | Mnemonic::Int3
                        | Mnemonic::INVALID
                ) {
                    break;
                }
                if matches!(i.mnemonic(), Mnemonic::Mov | Mnemonic::Movzx) {
                    if i.op0_kind() == OpKind::Register
                        && let Some(dest) = reg(i.op0_register())
                    {
                        registers[dest] = if i.op1_kind() == OpKind::Memory {
                            if absolute(&i) {
                                if u64::from(i.memory_displacement32()) == slot {
                                    Cell::Slot
                                } else if i.memory_size() == MemorySize::UInt8 {
                                    image
                                        .at_va(u64::from(i.memory_displacement32()))
                                        .and_then(|b| b.first())
                                        .map_or(Cell::Unknown, |b| Cell::Byte(*b))
                                } else {
                                    Cell::Unknown
                                }
                            } else if i.memory_displacement32() == 0
                                && i.memory_index() == Register::None
                                && reg(i.memory_base())
                                    .is_some_and(|r| matches!(registers[r], Cell::Slot))
                            {
                                Cell::Pointer
                            } else {
                                Cell::Unknown
                            }
                        } else if i.op1_kind() == OpKind::Register {
                            reg(i.op1_register()).map_or(Cell::Unknown, |r| registers[r])
                        } else {
                            Cell::Unknown
                        };
                    } else if i.op0_kind() == OpKind::Memory
                        && i.memory_size() == MemorySize::UInt8
                        && i.memory_index() == Register::None
                        && i.memory_displacement32() < 16
                        && reg(i.memory_base())
                            .is_some_and(|r| matches!(registers[r], Cell::Pointer))
                        && let Some(source) = reg(i.op1_register())
                        && let Cell::Byte(value) = registers[source]
                    {
                        let at = i.memory_displacement32() as usize;
                        if key[at].is_some_and(|old| old != value) {
                            return Err(missing("Conflicting Seen key construction"));
                        }
                        key[at] = Some(value);
                        break;
                    }
                } else if matches!(
                    i.mnemonic(),
                    Mnemonic::Xor | Mnemonic::Add | Mnemonic::Sub | Mnemonic::Lea
                ) && i.op0_kind() == OpKind::Register
                    && let Some(dest) = reg(i.op0_register())
                {
                    registers[dest] = Cell::Unknown;
                }
            }
        }
    }
    let mut bytes = [0; 16];
    for (dest, value) in bytes.iter_mut().zip(key) {
        *dest = value.ok_or_else(|| missing("Seen key construction is incomplete"))?;
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "../../tests/reallive/key.rs"]
mod tests;
