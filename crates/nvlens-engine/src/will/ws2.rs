//! AdvHD parameter tables, located through decoded x64 MOVZX/LEA/MOV or
//! x86 MOVZX/MOV table access (sub_4E4890). The x86 compiler can interleave
//! stack writes and use a different register for the loaded pointer.
//! Each byte opcode indexes one native-width pointer to signed type tags,
//! terminated by a negative byte; null pointers denote undefined opcodes.

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, MemorySize,
    Mnemonic, OpAccess, OpKind, Register,
};
use nvlens_core::{Error, Result};
use nvlens_io::{BinaryReader, pe::PeImage};
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) fn table(pe: &PeImage<'_>, cancel: &AtomicBool) -> Result<Option<Vec<u8>>> {
    let bitness = match pe.machine {
        0x14c => 32,
        0x8664 => 64,
        _ => return Ok(None),
    };
    let mut result = None;
    let mut info = InstructionInfoFactory::new();
    for section in pe.sections.iter().filter(|s| s.executable) {
        let data = pe.section_data(section)?;
        let mut decoder = Decoder::with_ip(
            bitness,
            data,
            pe.image_base + u64::from(section.virtual_address),
            DecoderOptions::NONE,
        );
        let mut previous = iced_x86::Instruction::default();
        let mut opcode_register = None;
        let mut decoded = 0usize;
        while decoder.can_decode() {
            if decoded.is_multiple_of(1024) && cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            decoded += 1;
            let current = decoder.decode();
            if bitness == 32
                && let Some(index) = opcode_register
                && let Some(address) = x86_table(index, &current)
                && let Some(candidate) = read_table(pe, address)
            {
                if result.as_ref().is_some_and(|old| old != &candidate) {
                    return Err(Error::UnknownScheme(Some(
                        "Conflicting AdvHD WS2 parameter tables".into(),
                    )));
                }
                result = Some(candidate);
            }
            if bitness == 32 {
                // Keep the zero-extended opcode only within straight-line code.
                // Instruction info includes partial and implicit register writes.
                if current.is_invalid() || current.flow_control() != FlowControl::Next {
                    opcode_register = None;
                } else if current.mnemonic() == Mnemonic::Movzx
                    && current.op0_kind() == OpKind::Register
                    && current.op0_register().is_gpr32()
                    && current.op1_kind() == OpKind::Memory
                    && current.memory_size() == MemorySize::UInt8
                {
                    opcode_register = Some(current.op0_register());
                } else if let Some(index) = opcode_register
                    && info.info(&current).used_registers().iter().any(|used| {
                        used.register().full_register() == index.full_register()
                            && matches!(
                                used.access(),
                                OpAccess::Write
                                    | OpAccess::CondWrite
                                    | OpAccess::ReadWrite
                                    | OpAccess::ReadCondWrite
                            )
                    })
                {
                    opcode_register = None;
                }
            }
            if bitness == 64
                && previous.mnemonic() == Mnemonic::Movzx
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

fn x86_table(index: Register, table_load: &Instruction) -> Option<u64> {
    if table_load.mnemonic() != Mnemonic::Mov
        || table_load.op0_kind() != OpKind::Register
        || !table_load.op0_register().is_gpr32()
        || table_load.op1_kind() != OpKind::Memory
        || table_load.memory_size() != MemorySize::UInt32
        || table_load.memory_base() != Register::None
        || table_load.memory_index() != index
        || table_load.memory_index_scale() != 4
    {
        return None;
    }
    // The table is an absolute PE data address in x86 builds. Its 256 native
    // pointers are validated by read_table before this candidate is accepted.
    Some(u64::from(table_load.memory_displacement32()))
}

fn read_table(pe: &PeImage<'_>, address: u64) -> Option<Vec<u8>> {
    let mut pointers = BinaryReader::new(pe.at_va(address)?);
    let mut out = Vec::new();
    let mut defined = false;
    for _ in 0..256 {
        let address = if pe.machine == 0x14c {
            u64::from(pointers.read_u32_le().ok()?)
        } else {
            pointers.read_u64_le().ok()?
        };
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
#[path = "../../tests/will/ws2.rs"]
mod tests;
