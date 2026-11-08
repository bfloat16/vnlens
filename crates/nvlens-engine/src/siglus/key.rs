//! Static x86 Siglus loader analysis, verified in sub_68EA00/sub_6984D0 and
//! sub_6A2360/sub_6ACDD0. Scattered bytes form a 16-byte stack key; actual XOR
//! loops bind it to a 256-byte table. Scene header fields +0x54/+0x58 identify
//! its optional key and compression; Gameexe's +4 guard identifies its key.
//! Instruction operands, loop targets and field offsets determine the role,
//! independently of register allocation, stack displacement or image base.
use super::missing;
use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};
use nvlens_core::{ArchiveOptions, Error, Result, Secret};
use nvlens_io::pe::PeImage;
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) fn parameters(image: &PeImage<'_>, cancel: &AtomicBool) -> Result<ArchiveOptions> {
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
    for slot in &mut slots {
        let load = decoder.decode();
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
        // Scheduling in the verified loaders interleaves ECX initialization or
        // an ESI stack load. Neither may change the byte register being copied.
        while store.mnemonic() == Mnemonic::Xor
            && store.op0_register() == Register::ECX
            && store.op1_register() == Register::ECX
            || store.mnemonic() == Mnemonic::Mov
                && store.op0_register() == Register::ESI
                && store.op1_kind() == OpKind::Memory
                && store.memory_base() == Register::EBP
        {
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
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;

    fn word(out: &mut Vec<u8>, value: u32) {
        let at = out.len();
        out.resize(at + 4, 0);
        BinaryWriter::u32_le(value, &mut out[at..]);
    }
    fn xor_code(out: &mut Vec<u8>, table: Option<u32>, wide: bool, alternate: bool) {
        let begin = out.len();
        let (index, pointer, counter) = if alternate { (7, 3, 6) } else { (1, 2, 3) };
        if let Some(table) = table {
            out.extend([0x8a, 0x80 | index]);
            word(out, table);
        } else if wide {
            out.extend([0x8a, 0x84, index * 8 + 5]);
            word(out, (-0x220i32) as u32);
        } else {
            out.extend([0x8a, 0x44, index * 8 + 5, 0xe0]);
        }
        out.extend([
            0x8d,
            0x40 | (pointer * 8) | pointer,
            1,
            0x30,
            0x40 | pointer,
            0xff,
            0x40 | index,
            0x81,
            0xe0 | index,
        ]);
        let mask = if table.is_some() { 255 } else { 15 };
        word(out, 0x80000000 | mask);
        out.extend([0x79, 8, 0x48 | index, 0x81, 0xc8 | index]);
        word(out, !mask);
        out.extend([0x40 | index, 0x48 | counter, 0x75]);
        out.push((begin as i32 - out.len() as i32 - 1) as i8 as u8);
    }
    fn loader_code(
        base: u32,
        scene: Option<u8>,
        wide: bool,
        alternate: bool,
        gap: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        if scene.is_none() {
            out.extend([0x83, 0x7a, 4, 0, 0x0f, 0x84]);
            word(&mut out, 0);
        }
        for i in (0..16).rev() {
            out.push(0xa0);
            word(&mut out, base + 0x2000 + i);
            if wide {
                out.extend([0x88, 0x85]);
                word(&mut out, (-0x220i32 + i as i32) as u32);
            } else {
                out.extend([0x88, 0x45, 0xe0 + i as u8]);
            }
        }
        if let Some(reg) = scene {
            for offset in [0x58, 0x54] {
                out.extend([0x83, 0x78 | reg, offset, 0]);
            }
        }
        xor_code(&mut out, None, wide, alternate);
        if scene.is_none() {
            let end = out.len() as u32;
            BinaryWriter::u32_le(end - 10, &mut out[6..]);
        }
        out.extend(gap);
        xor_code(
            &mut out,
            Some(base + if scene.is_some() { 0x1e00 } else { 0x1f00 }),
            wide,
            alternate,
        );
        out.push(0xc3);
        out
    }
    fn fixture(base: u32, register: u8, wide: bool, alternate: bool, gap: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 0x1400];
        bytes[..2].copy_from_slice(b"MZ");
        BinaryWriter::u32_le(0x80, &mut bytes[0x3c..]);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        for (offset, value) in [(0x84, 0x14c), (0x86, 1), (0x94, 0xe0), (0x98, 0x10b)] {
            BinaryWriter::u16_le(value, &mut bytes[offset..]);
        }
        for (offset, value) in [
            (0xb4, base),
            (0xd4, 0x200),
            (0x184, 0x1000),
            (0x188, 0x1200),
            (0x18c, 0x200),
            (0x19c, 0x20000000),
        ] {
            BinaryWriter::u32_le(value, &mut bytes[offset..]);
        }
        for i in 0..256 {
            bytes[0x1000 + i] = (i * 7) as u8;
            bytes[0x1100 + i] = (i * 13) as u8;
        }
        for i in 0..16 {
            bytes[0x1200 + i] = i as u8;
        }
        for (at, scene) in [(0x200, Some(register)), (0x600, None)] {
            let code = loader_code(base, scene, wide, alternate, gap);
            bytes[at..at + code.len()].copy_from_slice(&code);
        }
        bytes
    }
    #[test]
    fn relocated_loaders_accept_registers_stack_widths_and_alignment() -> Result<()> {
        for base in [0x400000, 0x610000] {
            for register in [0, 1, 2, 3, 5, 6, 7] {
                for (wide, alternate) in [(false, false), (true, true)] {
                    // JMP over LEA reg,[reg] is emitted for loop alignment.
                    let bytes = fixture(base, register, wide, alternate, &[0xeb, 3, 0x8d, 0x49, 0]);
                    let image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
                    let options = parameters(&image, &AtomicBool::new(false))?;
                    assert_eq!(
                        options.keys["siglus_game"].bytes(),
                        (0..16).collect::<Vec<u8>>()
                    );
                    assert_eq!(options.keys["siglus_scene"].bytes(), &bytes[0x1000..0x1100]);
                    assert_eq!(
                        options.keys["siglus_gameexe"].bytes(),
                        &bytes[0x1100..0x1200]
                    );
                }
            }
        }
        Ok(())
    }
    #[test]
    fn missing_roles_boundaries_broken_loops_and_cancellation_fail_closed() -> Result<()> {
        // True returns and non-padding tail jumps cannot bind a later loop.
        for gap in [&[0xc3][..], &[0xc2, 4, 0], &[0xeb, 2, 0x33, 0xc0]] {
            let bytes = fixture(0x400000, 1, false, false, gap);
            let image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
            assert!(matches!(
                parameters(&image, &AtomicBool::new(false)),
                Err(Error::UnknownScheme(_))
            ));
        }
        // RET opcodes and field-looking bytes inside an immediate are data.
        let bytes = fixture(0x400000, 1, false, false, &[0xb8, 0xc2, 4, 0, 0xc3]);
        let image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
        assert!(parameters(&image, &AtomicBool::new(false)).is_ok());
        assert!(matches!(
            parameters(&image, &AtomicBool::new(true)),
            Err(Error::Cancelled)
        ));
        for mutation in 0..4 {
            let mut bytes = fixture(0x400000, 1, false, false, &[]);
            match mutation {
                0 => bytes[0x200 + 128 + 2] = 0x59, // Missing compression field.
                1 => bytes[0x600 + 2] = 5,          // Missing Gameexe guard.
                2 => bytes[0x200 + 128 + 5] = 0x7a, // Different header bases.
                _ => {
                    let jump = Decoder::new(32, &bytes[0x200..0x600], DecoderOptions::NONE)
                        .into_iter()
                        .find(|i| i.mnemonic() == Mnemonic::Jne)
                        .ok_or(Error::InvalidFormat)?;
                    bytes[0x200 + jump.next_ip() as usize - 1] = 0;
                }
            }
            let image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
            assert!(matches!(
                parameters(&image, &AtomicBool::new(false)),
                Err(Error::UnknownScheme(_))
            ));
        }
        Ok(())
    }
    #[test]
    fn real_conflicts_are_reported_and_truncated_arrays_never_match() -> Result<()> {
        let mut bytes = fixture(0x400000, 1, false, false, &[]);
        let mut extra = loader_code(0x400000, Some(2), false, false, &[]);
        BinaryWriter::u32_le(0x402100, &mut extra[1..]);
        bytes[0xa00..0xa00 + extra.len()].copy_from_slice(&extra);
        let image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
        assert!(
            matches!(parameters(&image, &AtomicBool::new(false)), Err(Error::UnknownScheme(Some(reason))) if reason.contains("Conflicting"))
        );
        for length in 0..128 {
            assert!(key_array(&image, &bytes[0x200..0x200 + length], 0).is_none());
        }
        Ok(())
    }
}
