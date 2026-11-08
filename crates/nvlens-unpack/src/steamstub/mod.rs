//! SteamStub 3.1 x86's 0xF0-byte little-endian header precedes its entry stub.
//! Header words use adjacent-word XOR; signature is 0xC0DEC0DF. Code is AES-256
//! CBC with an ECB-decoded IV and a displaced first ciphertext block. These
//! layout facts are documented by Steamless's SteamStub32Var31Header and checked
//! against the protected and independently decoded COCORO code sections.
//! Only the code section is replaced. Payloads, DRM DLLs, imports, relocations,
//! executable headers and disk files are never rebuilt or executed.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use nvlens_core::{Error, Result};
use nvlens_crypto::cipher::{aes, xor};
use nvlens_io::{BinaryIo, BinaryReader, pe::PeImage};
use std::sync::atomic::{AtomicBool, Ordering};

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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ::aes::{
        Aes256,
        cipher::{BlockEncrypt, KeyInit},
    };
    use nvlens_io::BinaryWriter;

    const ENTRY: &[u8] = &[
        0xe8, 0, 0, 0, 0, 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x8b, 0x44, 0x24, 0x1c, 0x2d,
        5, 0, 0, 0, 0x8b, 0xcc, 0x83, 0xe4, 0xf0, 0x51, 0x51, 0x51, 0x50,
    ];

    fn fixture(tls: bool, flags: u32, code_size: u64) -> (Vec<u8>, Vec<u8>) {
        let mut bytes = vec![0; 0x600];
        bytes[..2].copy_from_slice(b"MZ");
        BinaryWriter::u32_le(0x80, &mut bytes[0x3c..]);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        for (at, value) in [(0x84, 0x14c), (0x86, 2), (0x94, 0xe0), (0x98, 0x10b)] {
            BinaryWriter::u16_le(value, &mut bytes[at..]);
        }
        for (at, value) in [
            (0xa8, if tls { 0x1000 } else { 0x2100 }),
            (0xb4, 0x400000),
            (0xd4, 0x200),
            (0xf4, 16),
        ] {
            BinaryWriter::u32_le(value, &mut bytes[at..]);
        }
        for (index, (name, rva, raw)) in [
            (*b".text\0\0\0", 0x1000, 0x200),
            (*b".bind\0\0\0", 0x2000, 0x400),
        ]
        .into_iter()
        .enumerate()
        {
            let at = 0x178 + index * 40;
            bytes[at..at + 8].copy_from_slice(&name);
            for (offset, value) in [
                (8, 0x200),
                (12, rva),
                (16, 0x200),
                (20, raw),
                (36, 0x60000020),
            ] {
                BinaryWriter::u32_le(value, &mut bytes[at + offset..]);
            }
        }
        if tls {
            BinaryWriter::u32_le(0x2180, &mut bytes[0x140..]);
            BinaryWriter::u32_le(24, &mut bytes[0x144..]);
            BinaryWriter::u32_le(0x4021a0, &mut bytes[0x58c..]);
            BinaryWriter::u32_le(0x402100, &mut bytes[0x5a0..]);
        }
        bytes[0x500..0x500 + ENTRY.len()].copy_from_slice(ENTRY);
        let plain: Vec<u8> = (0..32).map(|i| i * 3).collect();
        let cipher = Aes256::new((&[0x42; 32]).into());
        let mut iv = [0x31; 16];
        let mut encrypted_iv = iv;
        cipher.encrypt_block((&mut encrypted_iv).into());
        let mut encrypted = plain.clone();
        for block in encrypted.as_chunks_mut::<16>().0 {
            for (b, previous) in block.iter_mut().zip(iv) {
                *b ^= previous;
            }
            cipher.encrypt_block(block.into());
            iv = *block;
        }
        bytes[0x200..0x210].copy_from_slice(&encrypted[16..32]);
        let mut header = [0; HEADER_SIZE as usize];
        for (at, value) in [(0, 0x12345678), (4, 0xc0dec0df), (0x3c, flags)] {
            BinaryWriter::u32_le(value, &mut header[at..]);
        }
        for (at, value) in [
            (8, 0x400000),
            (16, 0x2100),
            (0x48, 0x1000),
            (0x50, code_size),
        ] {
            BinaryWriter::u64_le(value, &mut header[at..]);
        }
        header[0x58..0x78].fill(0x42);
        header[0x78..0x88].copy_from_slice(&encrypted_iv);
        header[0x88..0x98].copy_from_slice(&encrypted[..16]);
        let mut previous = BinaryReader::u32_le(&header);
        for word in header[4..].as_chunks_mut::<4>().0 {
            previous ^= BinaryReader::u32_le(word);
            BinaryWriter::u32_le(previous, word);
        }
        bytes[0x410..0x500].copy_from_slice(&header);
        (bytes, plain)
    }

    #[test]
    fn code_overlay_handles_entry_tls_plain_and_cancellation() -> Result<()> {
        for tls in [false, true] {
            let (bytes, plain) = fixture(tls, 0, 32);
            let mut image = PeImage::parse(&bytes)?.unwrap();
            let bind_before = image.at_rva(0x2000).unwrap().to_vec();
            assert!(unpack(&mut image, &AtomicBool::new(false))?);
            assert_eq!(&image.at_rva(0x1000).unwrap()[..32], plain);
            assert_eq!(image.at_rva(0x2000).unwrap(), bind_before);
            assert_eq!(image.at_rva(0x1020).unwrap(), &bytes[0x220..0x400]);
            assert_eq!(image.entry_point, if tls { 0x1000 } else { 0x2100 });
            let mut image = PeImage::parse(&bytes)?.unwrap();
            assert!(matches!(
                unpack(&mut image, &AtomicBool::new(true)),
                Err(Error::Cancelled)
            ));
            assert_eq!(image.at_rva(0x1000).unwrap(), &bytes[0x200..0x400]);
        }
        let (mut bytes, _) = fixture(false, 4, 32);
        let mut image = PeImage::parse(&bytes)?.unwrap();
        assert!(unpack(&mut image, &AtomicBool::new(false))?);
        assert_eq!(image.at_rva(0x1000).unwrap(), &bytes[0x200..0x400]);
        bytes[0x1a0..0x1a8].copy_from_slice(b".other\0\0");
        assert!(!unpack(
            &mut PeImage::parse(&bytes)?.unwrap(),
            &AtomicBool::new(false)
        )?);
        Ok(())
    }

    #[test]
    fn rejects_bad_ranges_headers_and_unknown_variants() -> Result<()> {
        for size in [17, 0x210, u64::MAX] {
            let (bytes, _) = fixture(false, 0, size);
            assert!(matches!(
                unpack(
                    &mut PeImage::parse(&bytes)?.unwrap(),
                    &AtomicBool::new(false)
                ),
                Err(Error::Corrupt { .. })
            ));
        }
        let (mut bytes, _) = fixture(false, 0, 32);
        bytes[0x414] ^= 1;
        assert!(matches!(
            unpack(
                &mut PeImage::parse(&bytes)?.unwrap(),
                &AtomicBool::new(false)
            ),
            Err(Error::Unsupported(_))
        ));
        let (mut bytes, _) = fixture(false, 0, 32);
        bytes[0x500] = 0;
        assert!(matches!(
            unpack(
                &mut PeImage::parse(&bytes)?.unwrap(),
                &AtomicBool::new(false)
            ),
            Err(Error::Unsupported(_))
        ));
        bytes.truncate(0x500);
        assert_eq!(
            PeImage::parse(&bytes).unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        Ok(())
    }

    #[test]
    fn entry_recognition_uses_operands_and_call_target() -> Result<()> {
        let (mut bytes, plain) = fixture(false, 0, 32);
        let mut entry = ENTRY.to_vec();
        // SUB EAX,5: sign-extended imm8 instead of the accumulator imm32 form.
        entry.splice(16..21, [0x83, 0xe8, 5]);
        // MOV ECX,ESP: the other opcode direction preserves its operands.
        entry[19..21].copy_from_slice(&[0x89, 0xe1]);
        bytes[0x500..0x580].fill(0);
        bytes[0x500..0x500 + entry.len()].copy_from_slice(&entry);
        let mut image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
        assert!(unpack(&mut image, &AtomicBool::new(false))?);
        assert_eq!(
            &image.at_rva(0x1000).ok_or(Error::InvalidFormat)?[..32],
            plain
        );
        bytes[0x501] = 1;
        let image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
        assert!(!entry_stub(&image, 0x2100));
        Ok(())
    }

    #[test]
    #[ignore = "Requires NVLENS_STEAMSTUB_EXE and NVLENS_STEAMSTUB_REFERENCE; compares existing local files without writing a PE"]
    fn compares_local_code_sections() -> Result<()> {
        let path = std::env::var_os("NVLENS_STEAMSTUB_EXE").ok_or(Error::InvalidFormat)?;
        let reference =
            std::env::var_os("NVLENS_STEAMSTUB_REFERENCE").ok_or(Error::InvalidFormat)?;
        let source = nvlens_io::ArcView::open(path)?;
        let expected = nvlens_io::ArcView::open(reference)?;
        let mut image =
            PeImage::parse(source.slice(0, source.len())?)?.ok_or(Error::InvalidFormat)?;
        let golden =
            PeImage::parse(expected.slice(0, expected.len())?)?.ok_or(Error::InvalidFormat)?;
        assert!(unpack(&mut image, &AtomicBool::new(false))?);
        for section in &golden.sections {
            assert_eq!(
                image
                    .at_rva(section.virtual_address)
                    .and_then(|b| b.get(..section.raw_size as usize)),
                Some(golden.section_data(section)?),
                "section {:?}",
                section.name
            );
        }
        println!(
            "All {} original sections match the independently decoded reference",
            golden.sections.len()
        );
        Ok(())
    }
}
