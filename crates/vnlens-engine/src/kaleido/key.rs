//! ADVENGINE startup constructs a std::string, then passes it and the period
//! to MFileReadTask's shared cipher setter (sub_1404D8570). The setter copies
//! the string and writes the period to a separate RIP-relative global.
use crate::context::Context;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic as M, OpKind, Register as R};
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_core::{ArchiveOptions, Error, Result, Secret};
use vnlens_io::pe::PeImage;

pub(super) fn resolve(
    context: &Context,
    paths: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<ArchiveOptions> {
    let mut found = None;
    let mut movie = None;
    for path in paths {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let view = context.files.open(path)?;
        let Some(image) = context.image(&view, cancel)? else {
            continue;
        };
        if !super::pe(&image)? {
            continue;
        }
        if let Some(candidate) = movie_parameters(&image, cancel)? {
            if movie
                .as_ref()
                .is_some_and(|previous| previous != &candidate)
            {
                return Err(Error::UnknownScheme(Some(
                    "Conflicting Kaleido movie cipher parameters".into(),
                )));
            }
            movie = Some(candidate);
        }
        for candidate in parameters(&image, cancel)? {
            if found
                .as_ref()
                .is_some_and(|previous| previous != &candidate)
            {
                return Err(Error::UnknownScheme(Some(
                    "Conflicting Kaleido filename cipher parameters".into(),
                )));
            }
            found = Some(candidate);
        }
    }
    let (key, length) = found.ok_or_else(|| {
        Error::UnknownScheme(Some(
            "Kaleido filename cipher initialization was not resolved".into(),
        ))
    })?;
    let movie = movie.ok_or_else(|| {
        Error::UnknownScheme(Some(
            "Kaleido movie cipher initialization was not resolved".into(),
        ))
    })?;
    let mut options = ArchiveOptions::default();
    options.keys.insert("kaleido_movie", Secret::new(movie));
    options.keys.insert("mdf_base", Secret::new(key));
    options.numbers.insert("mdf_length", u64::from(length));
    options.numbers.insert("kaleido", 1);
    Ok(options)
}

fn parameters(image: &PeImage<'_>, cancel: &AtomicBool) -> Result<Vec<(Vec<u8>, u32)>> {
    let mut result = Vec::new();
    if image.machine != 0x8664 {
        return Ok(result);
    }
    for section in image.sections.iter().filter(|section| section.executable) {
        let mut decoder = Decoder::with_ip(
            64,
            image.section_data(section)?,
            image.image_base + u64::from(section.virtual_address),
            DecoderOptions::NONE,
        );
        let mut recent = VecDeque::new();
        while decoder.can_decode() {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let instruction = decoder.decode();
            if instruction.mnemonic() == M::Nop {
                continue;
            }
            recent.push_back(instruction);
            if recent.len() > 6 {
                recent.pop_front();
            }
            if recent.len() != 6 {
                continue;
            }
            let i = recent.make_contiguous();
            if i[0].mnemonic() != M::Lea
                || i[0].op0_register() != R::RDX
                || !i[0].is_ip_rel_memory_operand()
                || !local(&i[1])
                || !call(&i[2])
                || i[3].mnemonic() != M::Mov
                || i[3].op0_register() != R::EDX
                || i[3].op1_kind() != OpKind::Immediate32
                || !local(&i[4])
                || i[1].memory_base() != i[4].memory_base()
                || i[1].memory_displacement64() != i[4].memory_displacement64()
                || !call(&i[5])
                || !setter(image, i[5].near_branch_target())
            {
                continue;
            }
            let Some(key) = image.c_string_at_va(i[0].ip_rel_memory_address()) else {
                continue;
            };
            if key.is_empty() || std::str::from_utf8(key).is_err() || i[3].immediate32() == 0 {
                continue;
            }
            result.push((key.to_vec(), i[3].immediate32()));
        }
    }
    Ok(result)
}
fn local(i: &Instruction) -> bool {
    i.mnemonic() == M::Lea
        && i.op0_register() == R::RCX
        && i.op1_kind() == OpKind::Memory
        && matches!(i.memory_base(), R::RSP | R::RBP)
        && i.memory_index() == R::None
}
fn call(i: &Instruction) -> bool {
    i.mnemonic() == M::Call && i.op0_kind() == OpKind::NearBranch64
}
fn setter(image: &PeImage<'_>, address: u64) -> bool {
    let Some(code) = image.at_va(address) else {
        return false;
    };
    let mut decoder = Decoder::with_ip(64, code, address, DecoderOptions::NONE);
    let mut global = None;
    let mut saved = R::None;
    let mut string_length = false;
    let mut inline_capacity = false;
    let mut copied = false;
    let mut period = false;
    while decoder.can_decode() {
        let i = decoder.decode();
        if i.is_invalid() {
            return false;
        }
        match i.mnemonic() {
            M::Lea if i.op0_register() == R::RAX && i.is_ip_rel_memory_operand() => {
                global = Some(i.ip_rel_memory_address())
            }
            M::Mov if i.op0_kind() == OpKind::Register && i.op1_register() == R::EDX => {
                saved = i.op0_register()
            }
            M::Cmp
                if i.op0_kind() == OpKind::Memory
                    && i.memory_base() == R::RCX
                    && i.memory_displacement64() == 24
                    && i.op1_kind() == OpKind::Immediate8to64
                    && i.immediate8to64() == 15 =>
            {
                inline_capacity = true
            }
            M::Mov
                if i.op0_register() == R::R8
                    && i.op1_kind() == OpKind::Memory
                    && i.memory_base() == R::RCX
                    && i.memory_displacement64() == 16 =>
            {
                string_length = true
            }
            M::Call if call(&i) && string_length && inline_capacity => copied = true,
            M::Mov
                if i.op0_kind() == OpKind::Memory
                    && i.is_ip_rel_memory_operand()
                    && saved != R::None
                    && i.op1_register() == saved =>
            {
                period = global.is_some_and(|global| global != i.ip_rel_memory_address());
            }
            M::Ret => return copied && period,
            M::Jmp => return false,
            _ => {}
        }
    }
    false
}

#[cfg(test)]
#[path = "../../tests/kaleido/key.rs"]
mod tests;

/// MkvFileReader::Open builds its own 4096-byte stream; its base string is
/// independent of the archive setter even when both reference the same literal.
/// sub_1400F6740 passes (path, base, 4096, this+0x30) to sub_1400F62B0.
pub(super) fn movie_parameters(
    image: &PeImage<'_>,
    cancel: &AtomicBool,
) -> Result<Option<Vec<u8>>> {
    if image.machine != 0x8664 {
        return Ok(None);
    }
    let mut found = None;
    for section in image.sections.iter().filter(|section| section.executable) {
        let mut decoder = Decoder::with_ip(
            64,
            image.section_data(section)?,
            image.image_base + u64::from(section.virtual_address),
            DecoderOptions::NONE,
        );
        let mut recent = VecDeque::new();
        while decoder.can_decode() {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let instruction = decoder.decode();
            if instruction.mnemonic() == M::Nop {
                continue;
            }
            recent.push_back(instruction);
            if recent.len() > 5 {
                recent.pop_front();
            }
            if recent.len() != 5 {
                continue;
            }
            let i = recent.make_contiguous();
            if i[0].mnemonic() != M::Lea
                || i[0].op0_register() != R::R9
                || i[0].op1_kind() != OpKind::Memory
                || i[0].memory_displacement64() != 0x30
                || i[1].mnemonic() != M::Mov
                || i[1].op0_register() != R::R8D
                || i[1].op1_kind() != OpKind::Immediate32
                || i[1].immediate32() != 4096
                || i[2].mnemonic() != M::Lea
                || i[2].op0_register() != R::RDX
                || !i[2].is_ip_rel_memory_operand()
                || i[3].mnemonic() != M::Mov
                || i[3].op0_register() != R::RCX
                || i[3].op1_kind() != OpKind::Register
                || !call(&i[4])
                || !movie_generator(image, i[4].near_branch_target())
            {
                continue;
            }
            let Some(key) = image.c_string_at_va(i[2].ip_rel_memory_address()) else {
                continue;
            };
            if key.is_empty() || std::str::from_utf8(key).is_err() {
                continue;
            }
            if found.as_deref().is_some_and(|previous| previous != key) {
                return Err(Error::UnknownScheme(Some(
                    "Conflicting Kaleido movie cipher parameters".into(),
                )));
            }
            found = Some(key.to_vec());
        }
    }
    Ok(found)
}
fn movie_generator(image: &PeImage<'_>, address: u64) -> bool {
    let Some(code) = image.at_va(address) else {
        return false;
    };
    let mut decoder = Decoder::with_ip(64, code, address, DecoderOptions::NONE);
    let mut constants = [false; 4];
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return false;
        }
        if instruction.mnemonic() == M::Ret {
            return constants.into_iter().all(|found| found);
        }
        for operand in 0..instruction.op_count() {
            if instruction.op_kind(operand) == OpKind::Immediate32 {
                for (seen, expected) in
                    constants
                        .iter_mut()
                        .zip([19_650_218, 1_812_433_253, 1_664_525, 1_566_083_941])
                {
                    *seen |= instruction.immediate32() == expected;
                }
            }
        }
    }
    false
}
