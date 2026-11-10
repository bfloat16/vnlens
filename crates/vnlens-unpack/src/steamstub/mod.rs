//! SteamStub 3.1 x86's 0xF0-byte little-endian header precedes its entry stub.
//! Header words use adjacent-word XOR; signature is 0xC0DEC0DF. Code is AES-256
//! CBC with an ECB-decoded IV and a displaced first ciphertext block. These
//! layout facts are documented by Steamless's SteamStub32Var31Header and checked
//! against the protected and independently decoded COCORO code sections.
//! Only the code section is replaced. Payloads, DRM DLLs, imports, relocations,
//! executable headers and disk files are never rebuilt or executed.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{Error, Result};
use vnlens_crypto::cipher::{aes, xor};
use vnlens_io::{BinaryIo, BinaryReader, pe::PeImage};

const HEADER_SIZE: u32 = 0xf0;

fn check(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

/// The entry obtains its own IP via CALL-next, saves registers, reconstructs
/// that address from the stack, then aligns ESP. Check decoded operands so
/// equivalent MOV/ADD/SUB encodings do not change wrapper recognition.
fn entry_stub(image: &PeImage<'_>, rva: u32) -> bool {
    let Some(bytes) = image.at_rva(rva) else {
        return false;
    };
    let mut decoder = Decoder::with_ip(32, bytes, u64::from(rva), DecoderOptions::NONE);
    let call = decoder.decode();
    if call.mnemonic() != Mnemonic::Call
        || call.op0_kind() != OpKind::NearBranch32
        || call.near_branch_target() != call.next_ip()
    {
        return false;
    }
    for register in [
        Register::EAX,
        Register::EBX,
        Register::ECX,
        Register::EDX,
        Register::ESI,
        Register::EDI,
        Register::EBP,
    ] {
        let i = decoder.decode();
        if i.mnemonic() != Mnemonic::Push || i.op0_register() != register {
            return false;
        }
    }
    let load = decoder.decode();
    if load.mnemonic() != Mnemonic::Mov
        || load.op0_register() != Register::EAX
        || load.op1_kind() != OpKind::Memory
        || load.memory_base() != Register::ESP
        || load.memory_index() != Register::None
        || load.memory_displacement32() != 7 * 4
    {
        return false;
    }
    let subtract = decoder.decode();
    if subtract.mnemonic() != Mnemonic::Sub
        || subtract.op0_register() != Register::EAX
        || immediate(&subtract) != Some(call.len() as u32)
    {
        return false;
    }
    let stack = decoder.decode();
    if stack.mnemonic() != Mnemonic::Mov
        || stack.op0_register() != Register::ECX
        || stack.op1_register() != Register::ESP
    {
        return false;
    }
    let align = decoder.decode();
    if align.mnemonic() != Mnemonic::And
        || align.op0_register() != Register::ESP
        || immediate(&align) != Some(0xfffffff0)
    {
        return false;
    }
    for register in [Register::ECX, Register::ECX, Register::ECX, Register::EAX] {
        let i = decoder.decode();
        if i.mnemonic() != Mnemonic::Push || i.op0_register() != register {
            return false;
        }
    }
    true
}
fn immediate(i: &Instruction) -> Option<u32> {
    match i.op1_kind() {
        OpKind::Immediate8to32 => Some(i.immediate8to32() as u32),
        OpKind::Immediate32 => Some(i.immediate32()),
        _ => None,
    }
}

/// Decodes a recognized SteamStub code section, returning false for unwrapped
/// images. Unsupported .bind wrappers and malformed recognized headers fail
/// explicitly. Call once on a freshly parsed image; cancellation leaves its
/// original section intact. No source bytes or filesystem paths are modified.
pub fn unpack(image: &mut PeImage<'_>, cancel: &AtomicBool) -> Result<bool> {
    check(cancel)?;
    let Some(bind) = image.sections.iter().find(|s| s.name == *b".bind\0\0\0") else {
        return Ok(false);
    };
    if image.machine != 0x14c {
        return Err(Error::Unsupported(
            "SteamStub machine is not supported".into(),
        ));
    }
    let mut entry = image.entry_point;
    if !entry_stub(image, entry) {
        entry = image
            .first_tls_callback()?
            .and_then(|va| va.checked_sub(image.image_base))
            .and_then(|rva| u32::try_from(rva).ok())
            .filter(|&rva| entry_stub(image, rva))
            .ok_or_else(|| Error::Unsupported("SteamStub entry variant is not supported".into()))?;
    }
    let header_rva = entry
        .checked_sub(HEADER_SIZE)
        .filter(|&rva| {
            rva.checked_sub(bind.virtual_address)
                .and_then(|offset| offset.checked_add(HEADER_SIZE))
                .is_some_and(|end| end <= bind.raw_size)
        })
        .ok_or_else(|| BinaryIo::unexpected_eof("SteamStub header exceeds its section"))?;
    let encoded = image
        .at_rva(header_rva)
        .and_then(|b| b.get(..HEADER_SIZE as usize))
        .ok_or_else(|| BinaryIo::unexpected_eof("SteamStub header exceeds section"))?;
    let mut header = encoded.to_vec();
    xor::decode_chained_u32(&mut header)?;
    let mut r = BinaryReader::new_at(&header, 4)?;
    if r.read_u32_le()? != 0xc0de_c0df {
        return Err(Error::Unsupported(
            "SteamStub header is not version 3.1".into(),
        ));
    }
    if r.read_u64_le()? != image.image_base || r.read_u64_le()? != u64::from(entry) {
        return Err(Error::Corrupt {
            offset: u64::from(header_rva),
            reason: "SteamStub image/entry addresses disagree with PE".into(),
        });
    }
    r.set_position(0x3c)?;
    let flags = r.read_u32_le()?;
    if flags & 4 != 0 {
        return Ok(true);
    }
    r.set_position(0x48)?;
    let code_rva = r.read_u64_le()?;
    let size = r.read_u64_le()?;
    let section = image
        .sections
        .iter()
        .find(|s| u64::from(s.virtual_address) == code_rva && s.executable)
        .ok_or_else(|| Error::Corrupt {
            offset: u64::from(header_rva),
            reason: "SteamStub code section is absent".into(),
        })?;
    if size > u64::from(section.raw_size) || !size.is_multiple_of(16) {
        return Err(Error::Corrupt {
            offset: u64::from(header_rva),
            reason: "SteamStub code length exceeds section or is not AES block aligned".into(),
        });
    }
    let mut key = [0; 32];
    key.copy_from_slice(r.read_bytes(32)?);
    let mut iv = [0; 16];
    iv.copy_from_slice(r.read_bytes(16)?);
    let stolen = r.read_bytes(16)?;
    let size = usize::try_from(size)
        .map_err(|_| BinaryIo::unexpected_eof("SteamStub code length does not fit memory"))?;
    let original = image.section_data(section)?;
    // The on-disk code starts at ciphertext block 1. The displaced block 0 is
    // in the header; the extra last block is padding and isn't part of the PE.
    let mut decoded = original.to_vec();
    if size != 0 {
        decoded[..16].copy_from_slice(stolen);
        decoded[16..size].copy_from_slice(&original[..size - 16]);
    }
    aes::decrypt_block(&key, &mut iv);
    for chunk in decoded[..size].chunks_mut(64 * 1024) {
        check(cancel)?;
        aes::decrypt_cbc(&key, &mut iv, chunk.as_chunks_mut::<16>().0);
    }
    check(cancel)?;
    image.replace_section(section.virtual_address, decoded)?;
    Ok(true)
}

#[cfg(test)]
#[path = "../../tests/steamstub/mod.rs"]
mod tests;
