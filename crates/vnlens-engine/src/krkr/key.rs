//! xp3dec's V2Link -> iTVPFunctionExporter::QueryFunctionsByNarrowString ->
//! TVPSetXP3ArchiveExtractionFilter chain and its 31-byte hash filter.
//! The verified x86 compiler form is checked by decoded operands and branch
//! targets, including the successful CRT remainder/cookie paths. Unknown
//! registration or callback code fails closed. No plugin code is executed.
mod internal;
use crate::{context::Context, detect::has};
use Mnemonic::*;
use Register::*;
use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_core::{ArchiveOptions, Error, Result};
use vnlens_io::pe::PeImage;

const API: &str = "void ::TVPSetXP3ArchiveExtractionFilter(tTVPXP3ArchiveExtractionFilter)";

pub(super) fn resolve(
    context: &Context,
    paths: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<ArchiveOptions> {
    let mut options = ArchiveOptions::default();
    for path in paths {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let view = context.files.open(path)?;
        let Some(image) = context.image(&view, cancel)? else {
            continue;
        };
        if let Some(recovered) = internal::resolve(&image, cancel)? {
            if options.numbers.contains_key("xp3_xor31")
                || (options.numbers.contains_key("xp3_cxdec") && options != recovered)
            {
                return Err(Error::UnknownScheme(Some(
                    "Conflicting KiriKiri XP3 filters".into(),
                )));
            }
            options = recovered;
            continue;
        }
        if xor31(&image)? {
            if options.numbers.contains_key("xp3_cxdec") {
                return Err(Error::UnknownScheme(Some(
                    "Conflicting KiriKiri XP3 filters".into(),
                )));
            }
            options.numbers.insert("xp3_xor31", 1);
        }
    }
    Ok(options)
}

fn xor31(image: &PeImage<'_>) -> Result<bool> {
    if !has(image, API.as_bytes())? {
        return Ok(false);
    }
    let Some(entry) = image.export(b"V2Link")? else {
        return Ok(false);
    };
    let matched = (image.machine == 0x14c)
        .then_some(entry)
        .and_then(|entry| registration(image, entry))
        .and_then(|callback| filter(image, callback));
    if matched.is_none() {
        return Err(Error::UnknownScheme(Some(
            "KiriKiri XP3 extraction plugin has an unsupported registration or filter".into(),
        )));
    }
    Ok(true)
}

#[derive(Clone, Copy)]
enum Operand {
    Reg(Register),
    Imm(u32),
    Mem(Register, Register, u32, u32, MemorySize),
}
use Operand::{Imm, Mem, Reg};
fn mem(base: Register, offset: u32) -> Operand {
    Mem(base, None, 1, offset, MemorySize::UInt32)
}
fn absolute(i: &Instruction) -> Option<u32> {
    (i.memory_base() == None
        && i.memory_index() == None
        && i.memory_size() == MemorySize::UInt32
        && matches!(i.segment_prefix(), None | DS | SS))
    .then(|| i.memory_displacement32())
}
fn immediate(i: &Instruction, op: u32) -> Option<u32> {
    match i.op_kind(op) {
        OpKind::Immediate8 => Some(u32::from(i.immediate8())),
        OpKind::Immediate16 => Some(u32::from(i.immediate16())),
        OpKind::Immediate32 => Some(i.immediate32()),
        OpKind::Immediate8to32 => Some(i.immediate8to32() as u32),
        _ => Option::None,
    }
}
struct Code<'a, 'b> {
    image: &'a PeImage<'b>,
    pc: u64,
}
impl<'a, 'b> Code<'a, 'b> {
    fn new(image: &'a PeImage<'b>, pc: u64) -> Self {
        Self { image, pc }
    }
    fn next(&mut self) -> Option<Instruction> {
        loop {
            if !self.image.sections.iter().any(|s| {
                s.executable
                    && self
                        .pc
                        .checked_sub(self.image.image_base + u64::from(s.virtual_address))
                        .is_some_and(|n| n < u64::from(s.raw_size))
            }) {
                return Option::None;
            }
            let mut d = Decoder::with_ip(
                32,
                self.image.at_va(self.pc)?,
                self.pc,
                DecoderOptions::NONE,
            );
            let i = d.decode();
            if i.is_invalid() || i.has_lock_prefix() {
                return Option::None;
            }
            self.pc = i.next_ip();
            if i.mnemonic() == Nop
                || (i.mnemonic() == Lea
                    && i.op0_register() == ESP
                    && i.memory_base() == ESP
                    && i.memory_index() == None
                    && i.memory_displacement32() == 0)
            {
                continue;
            }
            return Some(i);
        }
    }
    fn expect(&mut self, mnemonic: Mnemonic, operands: &[Operand]) -> Option<Instruction> {
        let i = self.next()?;
        if i.mnemonic() != mnemonic || i.op_count() as usize != operands.len() {
            return Option::None;
        }
        for (n, op) in operands.iter().enumerate() {
            let n = n as u32;
            let matches = match *op {
                Reg(r) => i.op_kind(n) == OpKind::Register && i.op_register(n) == r,
                Imm(v) => immediate(&i, n) == Some(v),
                Mem(base, index, scale, offset, size) => {
                    i.op_kind(n) == OpKind::Memory
                        && i.memory_base() == base
                        && i.memory_index() == index
                        && i.memory_index_scale() == scale
                        && i.memory_displacement32() == offset
                        && (mnemonic == Lea || i.memory_size() == size)
                        && matches!(i.segment_prefix(), None | SS | DS)
                }
            };
            if !matches {
                return Option::None;
            }
        }
        Some(i)
    }
    fn branch(&mut self, mnemonic: Mnemonic) -> Option<u64> {
        let i = self.next()?;
        (i.mnemonic() == mnemonic && i.op0_kind() == OpKind::NearBranch32)
            .then(|| i.near_branch_target())
    }
    fn constant(&mut self) -> Option<u32> {
        let i = self.next()?;
        if i.mnemonic() != Push {
            return Option::None;
        }
        immediate(&i, 0)
    }
    fn load_global(&mut self, register: Register) -> Option<u32> {
        let i = self.next()?;
        if i.mnemonic() != Mov || i.op0_register() != register || i.op1_kind() != OpKind::Memory {
            return Option::None;
        }
        absolute(&i)
    }
}

fn registration(image: &PeImage<'_>, entry: u64) -> Option<u64> {
    let mut c = Code::new(image, entry);
    c.expect(Mov, &[Reg(EAX), mem(ESP, 4)])?;
    let save = c.next()?;
    if save.mnemonic() != Mov || save.op0_kind() != OpKind::Memory || save.op1_register() != EAX {
        return Option::None;
    }
    let exporter = absolute(&save)?;
    let cache = c.load_global(EAX)?;
    if exporter == cache || image.u32_at_va(u64::from(cache)).ok()? != 0 {
        return Option::None;
    }
    c.expect(Test, &[Reg(EAX), Reg(EAX)])?;
    let cached = c.branch(Jne)?;
    if image.c_string_at_va(u64::from(c.constant()?))? != API.as_bytes() {
        return Option::None;
    }
    let resolver = c.branch(Call)?;
    query_exporter(image, resolver, exporter)?;
    c.expect(Add, &[Reg(ESP), Imm(4)])?;
    c.expect(Mov, &[mem(None, cache), Reg(EAX)])?;
    if c.pc != cached {
        return Option::None;
    }
    let callback = u64::from(c.constant()?);
    c.expect(Call, &[Reg(EAX)])?;
    c.expect(Xor, &[Reg(EAX), Reg(EAX)])?;
    c.expect(Ret, &[])?;
    Some(callback)
}

// The queried name is the caller's argument. QueryFunctionsByNarrowString
// receives its address and one output slot; EAX returns that slot on success.
fn query_exporter(image: &PeImage<'_>, entry: u64, exporter: u32) -> Option<()> {
    let mut c = Code::new(image, entry);
    c.expect(Push, &[Reg(ECX)])?;
    c.expect(Mov, &[Reg(EAX), mem(None, exporter)])?;
    c.expect(Mov, &[Reg(ECX), mem(EAX, 0)])?;
    c.expect(Push, &[Imm(1)])?;
    c.expect(Lea, &[Reg(EDX), mem(ESP, 4)])?;
    c.expect(Push, &[Reg(EDX)])?;
    c.expect(Lea, &[Reg(EDX), mem(ESP, 16)])?;
    c.expect(Push, &[Reg(EDX)])?;
    c.expect(Push, &[Reg(EAX)])?;
    c.expect(Mov, &[Reg(EAX), mem(ECX, 4)])?;
    c.expect(Call, &[Reg(EAX)])?;
    c.expect(Add, &[Reg(ESP), Imm(16)])?;
    c.expect(Test, &[Reg(AL), Reg(AL)])?;
    c.pc = c.branch(Jne)?;
    c.expect(Mov, &[Reg(EAX), mem(ESP, 0)])?;
    c.expect(Pop, &[Reg(ECX)])?;
    c.expect(Ret, &[])?;
    Some(())
}

fn filter(image: &PeImage<'_>, entry: u64) -> Option<()> {
    let mut c = Code::new(image, entry);
    c.expect(Sub, &[Reg(ESP), Imm(0x24)])?;
    let cookie = c.load_global(EAX)?;
    c.expect(Xor, &[Reg(EAX), Reg(ESP)])?;
    c.expect(Mov, &[mem(ESP, 0x20), Reg(EAX)])?;
    c.expect(Push, &[Reg(ESI)])?;
    c.expect(Push, &[Reg(EDI)])?;
    c.expect(Mov, &[Reg(EDI), mem(ESP, 0x30)])?;
    c.expect(Cmp, &[mem(EDI, 0), Imm(24)])?;
    // A real extraction call has sizeof(tTVPXP3ExtractionFilterInfo) == 24.
    // The other branch throws for an incompatible ABI, not a cipher variant.
    c.pc = c.branch(Je)?;
    c.expect(Mov, &[Reg(EAX), mem(EDI, 20)])?;
    c.expect(And, &[Reg(EAX), Imm(0x7fff_ffff)])?;
    c.expect(Mov, &[Reg(ECX), Reg(EAX)])?;
    c.expect(Shl, &[Reg(ECX), Imm(31)])?;
    c.expect(Or, &[Reg(EAX), Reg(ECX)])?;
    c.expect(Xor, &[Reg(ECX), Reg(ECX)])?;
    let key_loop = c.expect(Mov, &[Reg(EDX), Reg(EAX)])?.ip();
    c.expect(Mov, &[Mem(ESP, ECX, 1, 8, MemorySize::UInt8), Reg(AL)])?;
    c.expect(And, &[Reg(EDX), Imm(0xffff_fffe)])?;
    c.expect(Shl, &[Reg(EDX), Imm(23)])?;
    c.expect(Shr, &[Reg(EAX), Imm(8)])?;
    c.expect(Inc, &[Reg(ECX)])?;
    c.expect(Or, &[Reg(EAX), Reg(EDX)])?;
    c.expect(Cmp, &[Reg(ECX), Imm(31)])?;
    if c.branch(Jl)? != key_loop {
        return Option::None;
    }
    c.expect(Xor, &[Reg(ESI), Reg(ESI)])?;
    c.expect(Cmp, &[mem(EDI, 16), Reg(ESI)])?;
    let empty = c.branch(Jbe)?;
    c.expect(Push, &[Reg(EBX)])?;
    let data_loop = c.expect(Mov, &[Reg(EAX), mem(EDI, 12)])?.ip();
    c.expect(Xor, &[Reg(EDX), Reg(EDX)])?;
    c.expect(Mov, &[Reg(ECX), Reg(ESI)])?;
    c.expect(Add, &[Reg(ECX), mem(EDI, 4)])?;
    c.expect(Push, &[Imm(0)])?;
    c.expect(Adc, &[Reg(EDX), mem(EDI, 8)])?;
    c.expect(Push, &[Imm(31)])?;
    c.expect(Push, &[Reg(EDX)])?;
    c.expect(Push, &[Reg(ECX)])?;
    c.expect(Lea, &[Reg(EBX), Mem(EAX, ESI, 1, 0, MemorySize::Unknown)])?;
    remainder(image, c.branch(Call)?)?;
    c.expect(Mov, &[Reg(AL), Mem(ESP, EAX, 1, 12, MemorySize::UInt8)])?;
    c.expect(Xor, &[Mem(EBX, None, 1, 0, MemorySize::UInt8), Reg(AL)])?;
    c.expect(Inc, &[Reg(ESI)])?;
    c.expect(Cmp, &[Reg(ESI), mem(EDI, 16)])?;
    if c.branch(Jb)? != data_loop {
        return Option::None;
    }
    c.expect(Pop, &[Reg(EBX)])?;
    if c.pc != empty {
        return Option::None;
    }
    c.expect(Mov, &[Reg(ECX), mem(ESP, 0x28)])?;
    c.expect(Pop, &[Reg(EDI)])?;
    c.expect(Pop, &[Reg(ESI)])?;
    c.expect(Xor, &[Reg(ECX), Reg(ESP)])?;
    let mut guard = Code::new(image, c.branch(Call)?);
    guard.expect(Cmp, &[Reg(ECX), mem(None, cookie)])?;
    guard.branch(Jne)?;
    guard.expect(Ret, &[])?;
    c.expect(Add, &[Reg(ESP), Imm(0x24)])?;
    c.expect(Ret, &[Imm(4)])?;
    Some(())
}

// The call site proves divisor-high == 0 and divisor-low == 31. Only the
// corresponding CRT path is reachable: two unsigned divisions compute a
// 64-bit remainder, return it in EAX:EDX and remove all four stack arguments.
fn remainder(image: &PeImage<'_>, entry: u64) -> Option<()> {
    let mut c = Code::new(image, entry);
    c.expect(Push, &[Reg(EBX)])?;
    c.expect(Mov, &[Reg(EAX), mem(ESP, 20)])?;
    c.expect(Or, &[Reg(EAX), Reg(EAX)])?;
    c.branch(Jne)?;
    c.expect(Mov, &[Reg(ECX), mem(ESP, 16)])?;
    c.expect(Mov, &[Reg(EAX), mem(ESP, 12)])?;
    c.expect(Xor, &[Reg(EDX), Reg(EDX)])?;
    c.expect(Div, &[Reg(ECX)])?;
    c.expect(Mov, &[Reg(EAX), mem(ESP, 8)])?;
    c.expect(Div, &[Reg(ECX)])?;
    c.expect(Mov, &[Reg(EAX), Reg(EDX)])?;
    c.expect(Xor, &[Reg(EDX), Reg(EDX)])?;
    c.pc = c.branch(Jmp)?;
    c.expect(Pop, &[Reg(EBX)])?;
    c.expect(Ret, &[Imm(16)])?;
    Some(())
}

#[cfg(test)]
#[path = "../../tests/krkr/key.rs"]
mod tests;
