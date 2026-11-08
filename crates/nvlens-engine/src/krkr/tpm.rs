//! xp3dec's V2Link -> iTVPFunctionExporter::QueryFunctionsByNarrowString ->
//! TVPSetXP3ArchiveExtractionFilter chain and its 31-byte hash filter.
//! The verified x86 compiler form is checked by decoded operands and branch
//! targets, including the successful CRT remainder/cookie paths. Unknown
//! registration or callback code fails closed. No plugin code is executed.
use crate::detect::has;
use Mnemonic::*;
use Register::*;
use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};
use nvlens_core::{Error, Result};
use nvlens_io::pe::PeImage;

const API: &str = "void ::TVPSetXP3ArchiveExtractionFilter(tTVPXP3ArchiveExtractionFilter)";

pub(super) fn xor31(image: &PeImage<'_>) -> Result<bool> {
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
mod tests {
    use super::*;
    use nvlens_io::ArcView;
    #[test]
    #[ignore = "Requires NVLENS_KRKR_TPM pointing to a locally owned xp3dec plugin"]
    fn identifies_local_plugin() -> Result<()> {
        let path = std::env::var_os("NVLENS_KRKR_TPM").ok_or(Error::InvalidFormat)?;
        let view = ArcView::open(std::path::Path::new(&path))?;
        let image = PeImage::parse(view.slice(0, view.len())?)?.ok_or(Error::InvalidFormat)?;
        assert!(xor31(&image)?);
        Ok(())
    }
    use nvlens_io::BinaryWriter;
    use std::collections::BTreeMap;

    // Synthetic PE assembled from independent ABI/algorithm examples. Labels,
    // absolute operands and near branches are relocated for every fixture.
    struct Fixture {
        bytes: Vec<u8>,
        base: u32,
        at: usize,
        labels: BTreeMap<&'static str, usize>,
        branches: Vec<(usize, &'static str)>,
    }
    impl Fixture {
        fn emit(&mut self, bytes: &[u8]) {
            self.bytes[self.at..self.at + bytes.len()].copy_from_slice(bytes);
            self.at += bytes.len();
        }
        fn word(&mut self, value: u32) {
            BinaryWriter::u32_le(value, &mut self.bytes[self.at..]);
            self.at += 4;
        }
        fn va(&self, at: usize) -> u32 {
            self.base + 0x1000 + (at - 0x200) as u32
        }
        fn label(&mut self, name: &'static str) {
            self.labels.insert(name, self.at);
        }
        fn branch(&mut self, opcode: &[u8], label: &'static str) {
            self.emit(opcode);
            self.branches.push((self.at, label));
            self.word(0);
        }
        fn new(base: u32) -> Self {
            let mut f = Self {
                bytes: vec![0; 0x2200],
                base,
                at: 0x600,
                labels: BTreeMap::new(),
                branches: Vec::new(),
            };
            f.bytes[..2].copy_from_slice(b"MZ");
            f.bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
            for (at, value) in [(0x84, 0x14c), (0x86, 1), (0x94, 0xe0), (0x98, 0x10b)] {
                BinaryWriter::u16_le(value, &mut f.bytes[at..]);
            }
            for (at, value) in [
                (0x3c, 0x80),
                (0xb4, base),
                (0xd4, 0x200),
                (0xf4, 16),
                (0xf8, 0x1000),
                (0xfc, 0x100),
                (0x180, 0x3000),
                (0x184, 0x1000),
                (0x188, 0x2000),
                (0x18c, 0x200),
                (0x19c, 0xe0000020),
                (0x214, 1),
                (0x218, 1),
                (0x21c, 0x1060),
                (0x220, 0x1064),
                (0x224, 0x1068),
                (0x260, 0x1400),
                (0x264, 0x1080),
            ] {
                BinaryWriter::u32_le(value, &mut f.bytes[at..]);
            }
            f.bytes[0x280..0x287].copy_from_slice(b"V2Link\0");
            f.bytes[0x400..0x400 + API.len()].copy_from_slice(API.as_bytes());
            let exporter = base + 0x3900;
            let cache = base + 0x3904;
            let cookie = base + 0x3908;
            // V2Link and the function-exporter query.
            f.emit(&[0x90, 0x8b, 0x44, 0x24, 4, 0xa3]);
            f.word(exporter);
            f.emit(&[0xa1]);
            f.word(cache);
            f.emit(&[0x85, 0xc0]);
            f.branch(&[0x0f, 0x85], "cached");
            f.emit(&[0x68]);
            f.word(f.va(0x400));
            f.branch(&[0xe8], "query");
            f.emit(&[0x83, 0xc4, 4, 0xa3]);
            f.word(cache);
            f.label("cached");
            f.emit(&[0x68]);
            f.label("callback_pointer");
            f.word(0);
            f.emit(&[0xff, 0xd0, 0x31, 0xc0, 0xc3]);
            f.label("query");
            f.emit(&[0x51, 0xa1]);
            f.word(exporter);
            f.emit(&[
                0x8b, 8, 0x6a, 1, 0x8d, 0x54, 0x24, 4, 0x52, 0x8d, 0x54, 0x24, 16, 0x52, 0x50,
                0x8b, 0x41, 4, 0xff, 0xd0, 0x83, 0xc4, 16, 0x84, 0xc0,
            ]);
            f.branch(&[0x0f, 0x85], "queried");
            f.emit(&[0xcc]);
            f.label("queried");
            f.emit(&[0x8b, 4, 0x24, 0x59, 0xc3]);
            // Callback ABI, cookie and size guard.
            f.label("filter");
            f.emit(&[0x83, 0xec, 0x24, 0xa1]);
            f.word(cookie);
            f.emit(&[
                0x31, 0xe0, 0x89, 0x44, 0x24, 0x20, 0x56, 0x57, 0x8b, 0x7c, 0x24, 0x30, 0x83, 0x3f,
                24,
            ]);
            f.branch(&[0x0f, 0x84], "body");
            f.emit(&[0xcc]);
            f.label("body");
            f.emit(&[0x8b, 0x47, 20, 0x25]);
            f.word(0x7fffffff);
            // MOV uses the opposite direction encoding from the local plugin.
            f.emit(&[0x8b, 0xc8, 0xc1, 0xe1, 31, 0x09, 0xc8, 0x31, 0xc9]);
            f.label("key");
            f.emit(&[
                0x89, 0xc2, 0x88, 0x44, 0x0c, 8, 0x83, 0xe2, 0xfe, 0xc1, 0xe2, 23, 0xc1, 0xe8, 8,
                0x41, 0x09, 0xd0, 0x83, 0xf9,
            ]);
            f.label("period");
            f.emit(&[31]);
            f.branch(&[0x0f, 0x8c], "key");
            f.emit(&[0x31, 0xf6, 0x39, 0x77, 16]);
            f.branch(&[0x0f, 0x86], "end");
            f.emit(&[0x53]);
            f.label("data");
            f.emit(&[
                0x8b, 0x47, 12, 0x31, 0xd2, 0x89, 0xf1, 0x03, 0x4f, 4, 0x6a, 0, 0x13, 0x57,
            ]);
            f.label("offset_high");
            f.emit(&[8, 0x6a, 31, 0x52, 0x51, 0x8d, 0x1c, 0x30]);
            f.branch(&[0xe8], "remainder");
            f.emit(&[0x8a, 0x44, 4, 12]);
            f.label("xor");
            f.emit(&[0x30, 3, 0x46, 0x3b, 0x77, 16]);
            f.branch(&[0x0f, 0x82], "data");
            f.emit(&[0x5b]);
            f.label("end");
            f.emit(&[0x8b, 0x4c, 0x24, 0x28, 0x5f, 0x5e, 0x31, 0xe1]);
            f.branch(&[0xe8], "cookie");
            f.emit(&[0x83, 0xc4, 0x24, 0xc2, 4, 0]);
            // The reachable 64-bit dividend / 32-bit divisor CRT path.
            f.label("remainder");
            f.emit(&[0x53, 0x8b, 0x44, 0x24, 20, 0x09, 0xc0]);
            f.branch(&[0x0f, 0x85], "unsupported");
            f.emit(&[
                0x8b, 0x4c, 0x24, 16, 0x8b, 0x44, 0x24, 12, 0x31, 0xd2, 0xf7, 0xf1, 0x8b, 0x44,
                0x24, 8, 0xf7, 0xf1, 0x89, 0xd0, 0x31, 0xd2,
            ]);
            f.branch(&[0xe9], "remainder_end");
            f.label("unsupported");
            f.emit(&[0xcc]);
            f.label("remainder_end");
            f.emit(&[0x5b, 0xc2, 16, 0]);
            f.label("cookie");
            f.emit(&[0x3b, 0x0d]);
            f.word(cookie);
            f.branch(&[0x0f, 0x85], "unsupported");
            f.emit(&[0xc3]);
            for &(at, label) in &f.branches {
                BinaryWriter::u32_le(
                    (f.labels[label] as u32).wrapping_sub(at as u32 + 4),
                    &mut f.bytes[at..],
                );
            }
            let callback = f.va(f.labels["filter"]);
            BinaryWriter::u32_le(callback, &mut f.bytes[f.labels["callback_pointer"]..]);
            f
        }
    }
    #[test]
    fn follows_relocated_registration_and_rejects_changed_semantics() -> Result<()> {
        for base in [0x400000, 0x10000000] {
            let f = Fixture::new(base);
            let identify = |bytes: &[u8]| -> Result<bool> {
                xor31(&PeImage::parse(bytes)?.ok_or(Error::InvalidFormat)?)
            };
            assert!(identify(&f.bytes)?);
            for (label, value) in [("period", 30), ("offset_high", 4), ("xor", 0x00)] {
                let mut bytes = f.bytes.clone();
                bytes[f.labels[label]] = value;
                assert!(
                    matches!(identify(&bytes), Err(Error::UnknownScheme(_))),
                    "{label}"
                );
            }
            let mut bytes = f.bytes.clone();
            BinaryWriter::u32_le(
                f.va(f.labels["unsupported"]),
                &mut bytes[f.labels["callback_pointer"]..],
            );
            assert!(matches!(identify(&bytes), Err(Error::UnknownScheme(_))));
            bytes[0x400] = b'?';
            assert!(!identify(&bytes)?);
        }
        Ok(())
    }
}
