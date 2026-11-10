// Adapted from bfloat16/enigma_rs (Apache-2.0), commit 18fae558.
//! Reached x64 bootstrap instructions; counted XOR and LZ calls are summarized.
use super::super::Entry;
use super::cpu::{self as cpu, Image, State, Value};
use anyhow::{Context, Result, ensure};
use iced_x86::{Mnemonic as M, OpKind, Register as R};
use vnlens_crypto::compress::enigma as codec;
use vnlens_io::{
    BinaryReader, BinaryWriter,
    pe::{ImportSymbol, PeImage as Pe},
};

pub(in crate::enigma) fn parse(
    pe: &Pe<'_>,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<Entry> {
    let base = pe.image_base;
    let mut image = Image::default();
    image.add(
        base,
        BinaryReader::bytes_at(pe.file_bytes(), 0, pe.header_size as usize)?,
    )?;
    for s in &pe.sections {
        if s.raw_size != 0 {
            image.add(
                base + s.virtual_address as u64,
                BinaryReader::bytes_at(
                    pe.file_bytes(),
                    s.raw_offset as usize,
                    s.raw_size as usize,
                )?,
            )?;
        }
    }
    let imports = pe
        .imports()?
        .into_iter()
        .filter_map(|import| match import.symbol {
            ImportSymbol::Name(name) => {
                Some(String::from_utf8(name).map(|name| (import.slot, name)))
            }
            _ => None,
        })
        .collect::<std::result::Result<std::collections::HashMap<_, _>, _>>()?;
    let mut state = State::new(base + pe.entry_point as u64, 0x200100000);
    let mut loader = None;
    let mut loader_entry = None;
    let mut packed: Option<(u64, Vec<u8>)> = None;
    let mut checkpoint: Option<State> = None;
    let mut power = 1usize;
    let mut distance = 0usize;
    loop {
        crate::enigma::check(cancel)?;
        // Brent cycle detection compares complete interpreter states while
        // retaining one checkpoint, independent of the bootstrap's length.
        ensure!(
            checkpoint.as_ref() != Some(&state),
            "Enigma bootstrap contains a nonterminating cycle"
        );
        if checkpoint.is_none() || distance == power {
            checkpoint = Some(state.clone());
            power = power.saturating_mul(2);
            distance = 0;
        }
        distance += 1;
        if Some(state.pc) == loader_entry {
            return Ok(Entry {
                loader,
                metadata: u32::try_from(
                    cpu::reg(&state, R::R8)?.require("x64 metadata argument")?,
                )?,
            });
        }
        let i = image.instruction(state.pc)?;
        if i.mnemonic() == M::Ret && loader.is_none() && packed.is_none() {
            return Ok(Entry {
                loader: None,
                metadata: u32::try_from(
                    cpu::reg(&state, R::R8)?.require("x64 metadata argument")?,
                )?,
            });
        }
        if i.mnemonic() == M::Stmxcsr {
            state.pc = i.next_ip();
            continue;
        }
        if i.mnemonic() == M::Xor && i.op0_kind() == OpKind::Memory {
            let address = cpu::address(&state, &i)?.require("x64 XOR address")?;
            let width = i.memory_size().size();
            ensure!(matches!(width, 1 | 4), "unsupported x64 XOR width");
            let key = cpu::operand(&state, &image, &i, 1)?.require("x64 XOR key")?;
            let inc = image.instruction(i.next_ip())?;
            let dec = image.instruction(inc.next_ip())?;
            let branch = image.instruction(dec.next_ip())?;
            let pointer = i.memory_base();
            let counter = dec.op0_register();
            ensure!(
                i.memory_index() == R::None
                    && i.memory_displacement64() == 0
                    && pointer != counter
                    && i.op1_kind() == OpKind::Register
                    && i.op1_register().full_register() != pointer
                    && i.op1_register().full_register() != counter
                    && pointer.size() == 8
                    && counter.size() == 8
                    && inc.op0_register() == pointer
                    && ((inc.mnemonic() == M::Inc && width == 1)
                        || (inc.mnemonic() == M::Add && inc.immediate(1) == width as u64))
                    && dec.mnemonic() == M::Dec
                    && branch.mnemonic() == M::Jne
                    && branch.near_branch64() == i.ip(),
                "unsupported x64 counted XOR loop"
            );
            let count = cpu::reg(&state, counter)?.require("x64 XOR count")?;
            let length = usize::try_from(
                count
                    .checked_mul(width as u64)
                    .context("x64 XOR size overflow")?,
            )?;
            let mut key_bytes = [0; 8];
            BinaryWriter::u64_le(key, &mut key_bytes);
            let mut bytes = Vec::with_capacity(length);
            for n in 0..length {
                bytes.push(
                    state
                        .read(&image, address + n as u64, 1)
                        .require("x64 XOR source")? as u8
                        ^ key_bytes[n % width],
                );
            }
            cpu::set_reg(
                &mut state,
                pointer,
                Value::constant(address + length as u64),
            )?;
            cpu::set_reg(&mut state, counter, Value::constant(1))?;
            cpu::execute(&mut state, &image, &dec)?;
            state.pc = branch.next_ip();
            image.patch(address, &bytes)?;
            if width == 4 {
                ensure!(packed.is_none(), "multiple x64 packed runtimes");
                packed = Some((address, bytes));
            }
            continue;
        }
        if i.mnemonic() == M::Call {
            if let Some((source, bytes)) = &packed
                && loader.is_none()
                && cpu::reg(&state, R::RCX)?.get() == Some(*source)
                && cpu::reg(&state, R::RAX)?
                    .get()
                    .is_some_and(|n| n >= bytes.len() as u64 && n < bytes.len() as u64 + 4)
            {
                let dest = cpu::reg(&state, R::RDX)?.require("x64 runtime destination")?;
                let rva = u32::try_from(dest.checked_sub(base).context("runtime below host")?)?;
                let section = pe
                    .section_at(rva)
                    .context("runtime destination outside image")?;
                ensure!(
                    section.virtual_address == rva,
                    "runtime destination is not section start"
                );
                let mut stream = bytes.clone();
                let length = cpu::reg(&state, R::RAX)?.require("Loader length")? as usize;
                stream.extend(pe.read(
                    u32::try_from(source - base)? + bytes.len() as u32,
                    length - bytes.len(),
                )?);
                let mut decoded = codec::decompress(&stream, section.virtual_size as usize, false)?;
                codec::fix_branches(&mut decoded);
                let dll = Pe::parse(&decoded)?.context("Missing x64 Loader PE")?;
                ensure!(
                    dll.machine == 0x8664,
                    "x64 bootstrap decoded another architecture"
                );
                loader_entry = Some(dest + dll.entry_point as u64);
                checkpoint = None;
                image.replace_region(dest, decoded.clone())?;
                loader = Some(decoded);
                state.pc = i.next_ip();
                continue;
            }
            if i.op0_kind() == OpKind::Memory {
                let slot = cpu::address(&state, &i)?.require("x64 API slot")?;
                let name = imports.get(&slot).context("unknown x64 bootstrap API")?;
                ensure!(
                    matches!(
                        name.as_str(),
                        "LoadLibraryA" | "GetProcAddress" | "GetModuleHandleA"
                    ),
                    "unsupported x64 bootstrap API {name}"
                );
                state.registers[0] = Value::constant(0x700000000);
                state.flags = Value::unknown_flags();
                state.pc = i.next_ip();
                continue;
            }
        }
        ensure!(
            cpu::execute(&mut state, &image, &i)
                .with_context(|| format!("x64 bootstrap at {:#x} {:?}", i.ip(), i.mnemonic()))?
                .is_none(),
            "x64 bootstrap depends on unknown input"
        );
    }
}
