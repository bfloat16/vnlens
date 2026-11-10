// Adapted from bfloat16/enigma_rs (Apache-2.0), commit 18fae558.
//! Follow the reached entry instructions and summarize proven counted XOR loops.
//! Embedded junk and unreachable code do not supply decoding parameters.
use anyhow::{Context, Result, bail, ensure};
use iced_x86::{FlowControl, Instruction, Mnemonic as M, OpKind, Register as R};

use super::cpu::{self as x86, Image, State, Value};
use vnlens_crypto::compress::enigma as codec;
use vnlens_io::{
    BinaryReader, BinaryWriter,
    pe::{ImportSymbol, PeImage as Pe},
};

use super::super::Entry;

struct Xor {
    address: u32,
    length: usize,
    key: u32,
}

fn counted_xor(image: &mut Image, state: &mut State, first: Instruction) -> Result<Xor> {
    let width = first.memory_size().size() as u32;
    ensure!(matches!(width, 1 | 4), "unsupported entry XOR width");
    let address = x86::address(state, &first)?.require("entry XOR pointer")?;
    let key = x86::operand(state, image, &first, 1)?.require("entry XOR key")?;
    let mut body = vec![first];
    let mut pc = first.next_ip32();
    let branch = loop {
        let i = image.instruction(pc)?;
        if i.mnemonic() == M::Jne {
            ensure!(
                i.near_branch32() == first.ip32(),
                "entry XOR loop has another edge"
            );
            break i;
        }
        ensure!(
            i.flow_control() == FlowControl::Next
                && i.op_kind(0) == OpKind::Register
                && matches!(
                    i.mnemonic(),
                    M::Inc | M::Dec | M::Add | M::Sub | M::Lea | M::Nop
                ),
            "unsupported entry XOR loop effect"
        );
        ensure!(
            body.len() < 3,
            "entry XOR loop does not have pointer/counter updates"
        );
        pc = i.next_ip32();
        body.push(i);
    };
    // The final flag producer must decrement the loop counter by one.
    let decrement = body.last().context("missing entry XOR decrement")?;
    let counter = decrement.op_register(0).full_register32();
    ensure!(
        decrement.op_register(0) == counter,
        "entry XOR counter is not 32-bit"
    );
    ensure!(
        decrement.mnemonic() == M::Dec
            || (decrement.mnemonic() == M::Sub
                && x86::operand(state, image, decrement, 1)?.get() == Some(1)),
        "entry XOR has no unit counter decrement"
    );
    let pointer = first.memory_base().full_register32();
    ensure!(
        first.memory_index() == R::None && first.memory_displacement32() == 0 && pointer != counter,
        "unsupported entry XOR addressing"
    );
    let count = x86::reg(state, counter)?.require("entry XOR count")?;
    let length = (count as usize)
        .checked_mul(width as usize)
        .context("entry XOR length overflow")?;
    // Restrict updates to a unit counter decrement and a constant pointer
    // stride. No data-dependent update may supply the induction invariant.
    ensure!(
        body.len() == 3
            && body[1].op_register(0).full_register32() == pointer
            && body[2].op_register(0).full_register32() == counter,
        "entry XOR loop does not have independent pointer/counter updates"
    );
    let advance = &body[1];
    ensure!(
        advance.op_register(0) == pointer,
        "entry XOR pointer update is not 32-bit"
    );
    ensure!(
        (advance.mnemonic() == M::Inc && width == 1)
            || (advance.mnemonic() == M::Add
                && x86::operand(state, image, advance, 1)?.get() == Some(width)),
        "entry XOR pointer stride disagrees with its memory width"
    );
    let mut proof = state.clone();
    let counter_index = x86::register(counter)?.0;
    let pointer_index = x86::register(pointer)?.0;
    proof.registers[counter_index] = Value::constant(2);
    proof.registers[pointer_index] = Value::constant(address);
    let before = proof.registers;
    for i in &body {
        ensure!(
            x86::execute(&mut proof, image, i)?.is_none(),
            "entry XOR branches"
        );
    }
    for (index, original) in before.into_iter().enumerate() {
        let expected = if index == counter_index {
            Value::constant(1)
        } else if index == pointer_index {
            Value::constant(address.wrapping_add(width))
        } else {
            original
        };
        ensure!(
            proof.registers[index] == expected,
            "entry XOR changes another register"
        );
    }
    ensure!(
        x86::operand(&proof, image, &first, 1)?.get() == Some(key),
        "entry XOR key changes"
    );
    // Run the last iteration only to recover the precise exit flags.
    let mut last = state.clone();
    last.registers[counter_index] = Value::constant(1);
    last.registers[pointer_index] = Value::constant(
        address
            .checked_add(length as u32 - width)
            .context("entry XOR range overflow")?,
    );
    for i in &body {
        x86::execute(&mut last, image, i)?;
    }
    ensure!(
        last.registers[counter_index].get() == Some(0),
        "entry XOR does not terminate"
    );
    state.registers = last.registers;
    state.flags = last.flags;
    state.pc = branch.next_ip32();
    Ok(Xor {
        address,
        length,
        key,
    })
}

fn host_imports(pe: &Pe<'_>, _base: u32) -> Result<std::collections::HashMap<u32, String>> {
    pe.imports()?
        .into_iter()
        .filter_map(|import| match import.symbol {
            ImportSymbol::Name(name) => Some((|| {
                Ok((u32::try_from(import.slot)?, String::from_utf8(name)?))
            })()),
            _ => None,
        })
        .collect()
}

pub(crate) fn parse(pe: &Pe<'_>, cancel: &std::sync::atomic::AtomicBool) -> Result<Entry> {
    let base = u32::try_from(pe.image_base)?;
    let mut image = Image::default();
    image.add(
        base,
        BinaryReader::bytes_at(pe.file_bytes(), 0, pe.header_size as usize)?,
    )?;
    for section in &pe.sections {
        if section.raw_size != 0 {
            image.add(
                base.checked_add(section.virtual_address)
                    .context("entry image address overflow")?,
                BinaryReader::bytes_at(
                    pe.file_bytes(),
                    section.raw_offset as usize,
                    section.raw_size as usize,
                )?,
            )?;
        }
    }
    let imports = host_imports(pe, base).context("entry host import table")?;
    let mut state = State::new(
        base.checked_add(pe.entry_point)
            .context("entry address overflow")?,
        0x20000000,
    );
    let mut loader = None;
    let mut packed = None;
    let mut loader_entry = None;
    let mut layers = 0;
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
            let metadata = state
                .read(&image, state.esp()? + 8, 4)
                .require("Loader metadata argument")?;
            ensure!(loader.is_some(), "entry did not decode a Loader");
            return Ok(Entry { loader, metadata });
        }
        let i = image.instruction(state.pc)?;
        if i.mnemonic() == M::Ret && loader.is_none() && packed.is_none() && layers == 0 {
            let metadata = state
                .read(&image, state.esp()?, 4)
                .require("metadata argument")?;
            return Ok(Entry {
                loader: None,
                metadata,
            });
        }
        if i.mnemonic() == M::Xor && i.op_kind(0) == OpKind::Memory {
            let width = i.memory_size().size();
            let operation = counted_xor(&mut image, &mut state, i)?;
            let rva = operation
                .address
                .checked_sub(base)
                .context("entry XOR precedes image")?;
            let mut bytes = if width == 1 {
                // Nested layers use the already decrypted static image.
                (0..operation.length)
                    .map(|n| {
                        state
                            .read(&image, operation.address + n as u32, 1)
                            .require("entry ciphertext byte")
                            .map(|b| b as u8)
                    })
                    .collect::<Result<Vec<_>>>()?
            } else {
                pe.read(rva, operation.length)
                    .with_context(|| {
                        format!(
                            "entry Loader XOR source {rva:#x}, length {:#x}",
                            operation.length
                        )
                    })?
                    .to_vec()
            };
            let mut key = [0; 4];
            BinaryWriter::u32_le(operation.key, &mut key);
            vnlens_crypto::cipher::xor::apply(&mut bytes, &key[..width])?;
            if width == 1 {
                layers += 1;
                image.patch(operation.address, &bytes)?;
                checkpoint = None;
            } else {
                ensure!(packed.is_none(), "multiple Loader ciphertext loops");
                packed = Some((operation, bytes));
            }
            continue;
        }
        if i.mnemonic() == M::Call {
            if let Some((operation, bytes)) = &packed {
                let esp = state.esp()?;
                let destination = state.read(&image, esp, 4).get();
                let packed_length = state.read(&image, esp + 8, 4).get();
                if state.read(&image, esp + 4, 4).get() == Some(operation.address)
                    && packed_length.is_some_and(|length| {
                        length as usize >= operation.length
                            && (length as usize) < operation.length + 4
                    })
                    && let Some(destination) = destination
                {
                    let rva = destination
                        .checked_sub(base)
                        .context("Loader precedes host")?;
                    let section = pe
                        .section_at(rva)
                        .context("Loader destination has no section")?;
                    ensure!(
                        section.virtual_address == rva,
                        "Loader destination is not a section base"
                    );
                    let mut stream = bytes.clone();
                    let tail =
                        packed_length.context("Missing Loader length")? as usize - stream.len();
                    if tail != 0 {
                        stream.extend(
                            pe.read(operation.address - base + operation.length as u32, tail)?,
                        );
                    }
                    let mut decoded =
                        codec::decompress(&stream, section.virtual_size as usize, false)
                            .context("Loader decompression failed")?;
                    codec::fix_branches(&mut decoded);
                    let parsed = Pe::parse(&decoded)?.context("decoded Loader PE")?;
                    loader_entry = Some(
                        destination
                            .checked_add(parsed.entry_point)
                            .context("Loader entry overflow")?,
                    );
                    // Loader expansion is a mapped image in these ABIs.
                    checkpoint = None;
                    image.replace_region(destination, decoded.clone())?;
                    loader = Some(decoded);
                    state.registers[4] = Value::constant(esp + 12);
                    state.registers[0] = Value::UNKNOWN;
                    state.flags = Value::unknown_flags();
                    state.pc = i.next_ip32();
                    continue;
                }
            }
            if i.op_kind(0) == OpKind::Memory {
                let slot = x86::address(&state, &i)?.require("entry API slot")?;
                let name = imports
                    .get(&slot)
                    .context("entry calls an unknown API slot")?;
                let consumed = match name.as_str() {
                    "LoadLibraryA" | "GetModuleHandleA" => 4,
                    "GetProcAddress" => 8,
                    _ => bail!("unsupported entry API {name}"),
                };
                // Follow the successful PE Loader setup path. This placeholder
                // represents a non-null handle/address, never target API execution.
                state.registers[0] = Value::constant(0x70000000);
                state.registers[4] = Value::constant(state.esp()? + consumed);
                state.flags = Value::unknown_flags();
                state.pc = i.next_ip32();
                continue;
            }
        }
        if i.mnemonic() == M::Push && i.memory_segment() == R::FS {
            state.push(&image, Value::UNKNOWN)?;
            state.pc = i.next_ip32();
            continue;
        }
        ensure!(
            x86::execute(&mut state, &image, &i)
                .with_context(|| format!("entry {:#x} {:?}", i.ip(), i.mnemonic()))?
                .is_none(),
            "entry decoding depends on an unknown branch"
        );
    }
}
