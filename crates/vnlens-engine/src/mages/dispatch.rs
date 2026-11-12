//! Resolve SC3 handler-table variants from PE pointer records and iced-x86.
//! Table identities use shared handler aliases in funcs_14008E635/655/675;
//! references must also occur as decoded LEA operands or indexed indirect calls.
//! Only leaf layouts needed by the script reader are exported, never host VAs.
use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind};
use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_core::{Error, Result};
use vnlens_io::{BinaryReader, pe::PeImage};

pub(super) fn layouts(pe: &PeImage<'_>, cancel: &AtomicBool) -> Result<Option<(u64, u64)>> {
    if pe.machine != 0x8664 {
        return Ok(None);
    }
    let mut references = BTreeSet::new();
    for section in pe.sections.iter().filter(|s| s.executable) {
        let mut decoder = Decoder::with_ip(
            64,
            pe.section_data(section)?,
            pe.image_base + u64::from(section.virtual_address),
            DecoderOptions::NONE,
        );
        while decoder.can_decode() {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let i = decoder.decode();
            if i.mnemonic() == Mnemonic::Lea && i.op1_kind() == OpKind::Memory {
                if i.is_ip_rel_memory_operand() {
                    references.insert(i.ip_rel_memory_address());
                }
            } else if i.flow_control() == FlowControl::IndirectCall
                && i.op0_kind() == OpKind::Memory
                && i.memory_index_scale() == 8
            {
                let displacement = i.memory_displacement64();
                references.insert(displacement);
                if let Some(va) = pe.image_base.checked_add(displacement) {
                    references.insert(va);
                }
            }
        }
    }
    let mut tables: [Option<Vec<u64>>; 3] = [None, None, None];
    for address in references {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let Some(bytes) = pe.at_va(address) else {
            continue;
        };
        if bytes.len() < 65 * 8 {
            continue;
        }
        let mut reader = BinaryReader::new(bytes);
        let mut values = Vec::new();
        for _ in 0..97 {
            if reader.remaining() < 8 {
                break;
            }
            let va = reader.read_u64_le()?;
            let executable = va
                .checked_sub(pe.image_base)
                .and_then(|rva| u32::try_from(rva).ok())
                .and_then(|rva| pe.section_at(rva))
                .is_some_and(|s| s.executable);
            if !executable {
                break;
            }
            values.push(va);
        }
        if values.len() < 65 {
            continue;
        }
        let same = |slots: &[usize]| slots.iter().all(|&i| values.get(i) == values.get(slots[0]));
        let table = if values.len() >= 97
            && same(&[0x1d, 0x42, 0x4f])
            && same(&[0x36, 0x49, 0x4a])
            && values[0x1d] != values[0x36]
            && values[7] != values[0xb]
        {
            Some((0, 97))
        } else if same(&[0x32, 0x33, 0x34, 0x35, 0x40])
            && values[0xc] != values[0xd]
            && values[0xc] != values[0x32]
            && values[0x10] != values[0x11]
        {
            Some((1, 65))
        } else if same(&[0x18, 0x25, 0x26, 0x2b, 0x31, 0x35, 0x38, 0x39, 0x3e])
            && values[1] != values[2]
            && values[0x18] != values[1]
            && values[0x30] != values[0x33]
        {
            Some((2, 65))
        } else {
            None
        };
        if let Some((index, size)) = table {
            values.truncate(size);
            if tables[index].as_ref().is_some_and(|old| old != &values) {
                return Err(Error::Unsupported(
                    "Ambiguous MAGES SC3 dispatch table".into(),
                ));
            }
            tables[index] = Some(values);
        }
    }
    let [Some(system), Some(text), Some(layer)] = tables else {
        return Ok(None);
    };
    let evaluate = calls(pe, system[0x1d], cancel)?;
    let wait = calls(pe, system[5], cancel)?;
    let copy = calls(pe, system[0x14], cancel)?;
    let mut shared = evaluate
        .into_iter()
        .filter(|v| wait.contains(v) && copy.iter().filter(|&p| p == v).count() == 2);
    let Some(expression) = shared.next() else {
        return Ok(None);
    };
    if shared.next().is_some() {
        return Ok(None);
    }
    let count = |va| -> Result<u64> {
        Ok(calls(pe, va, cancel)?
            .iter()
            .filter(|&&v| v == expression)
            .count() as u64)
    };
    Ok(Some((count(text[3])?, count(layer[0x36])?)))
}

fn calls(pe: &PeImage<'_>, address: u64, cancel: &AtomicBool) -> Result<Vec<u64>> {
    let range = pe.runtime_function(address)?;
    let bytes = range
        .or_else(|| pe.at_va(address))
        .ok_or_else(|| Error::Unsupported("Unmapped MAGES handler".into()))?;
    let mut decoder = Decoder::with_ip(64, bytes, address, DecoderOptions::NONE);
    let mut found = Vec::new();
    // Unwind ranges include branch bodies after an early return. Tiny leaf
    // handlers without unwind records terminate at RET or a tail jump.
    while decoder.can_decode() {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let i = decoder.decode();
        if i.is_invalid() || i.mnemonic() == Mnemonic::Int3 {
            break;
        }
        if i.mnemonic() == Mnemonic::Ret && range.is_none() {
            break;
        }
        if i.flow_control() == FlowControl::Call && i.op0_kind() == OpKind::NearBranch64 {
            found.push(i.near_branch_target());
        }
        if i.flow_control() == FlowControl::UnconditionalBranch
            && i.op0_kind() == OpKind::NearBranch64
            && (range.is_none()
                || !(address..address + bytes.len() as u64).contains(&i.near_branch_target()))
        {
            found.push(i.near_branch_target());
            if range.is_none() {
                break;
            }
        }
    }
    Ok(found)
}
