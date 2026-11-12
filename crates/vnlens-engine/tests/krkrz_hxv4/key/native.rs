use super::*;
use vnlens_core::Error;
fn word(out: &mut Vec<u8>, value: u32) {
    let at = out.len();
    out.resize(at + 4, 0);
    BinaryWriter::u32_le(value, &mut out[at..]);
}
fn call(out: &mut Vec<u8>, target: u32) {
    out.push(0xe8);
    word(out, target.wrapping_sub(out.len() as u32 + 4));
}
fn fixture(base: u32, alternate: bool) -> Vec<u8> {
    let mut bytes = vec![0; 0x2600];
    bytes[..2].copy_from_slice(b"MZ");
    BinaryWriter::u32_le(0x80, &mut bytes[0x3c..]);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    for (at, n) in [(0x84, 0x14c), (0x86, 1), (0x94, 0xe0), (0x98, 0x10b)] {
        BinaryWriter::u16_le(n, &mut bytes[at..]);
    }
    for (at, n) in [
        (0xb4, base),
        (0xd4, 0x200),
        (0x184, 0x1000),
        (0x188, 0x2400),
        (0x18c, 0x200),
        (0x19c, 0x20000000),
    ] {
        BinaryWriter::u32_le(n, &mut bytes[at..]);
    }
    let mut code = Vec::new();
    code.extend([if alternate { 0x81 } else { 0x83 }, 0x3d]);
    word(&mut code, base + 0x1300);
    if alternate {
        word(&mut code, 0);
        code.extend([0x76, 20]);
    } else {
        code.push(0);
        code.extend([0x0f, 0x86]);
        word(&mut code, 20);
    }
    for (slot, value) in [(base + 0x1310, base + 0x1400), (base + 0x1314, 0x2000)] {
        code.extend([0xc7, 5]);
        word(&mut code, slot);
        word(&mut code, value);
    }
    code.push(0xc3);
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    let mut code = Vec::new();
    for (offset, value) in [(0, 0x12345678), (4, 0x9abcdef0)] {
        code.extend([0xc7, if alternate { 0x85 } else { 0x45 }]);
        if alternate {
            word(&mut code, (-0x120i32 + offset) as u32);
        } else {
            code.push((0xe0 + offset) as u8);
        }
        word(&mut code, value);
    }
    let reg = if alternate { 7 } else { 6 };
    code.extend([0x0f, 0x45, 0xc0 | (reg * 8)]);
    call(&mut code, 0x500);
    code.extend([0xff, 0x30 | reg]);
    if alternate {
        code.push(0x68);
        word(&mut code, 8);
    } else {
        code.extend([0x6a, 8]);
    }
    code.push(0x50 | reg);
    call(&mut code, 0x500);
    code.push(0xc3);
    bytes[0x300..0x300 + code.len()].copy_from_slice(&code);
    bytes[0x600..].fill(0x5a);
    bytes
}
#[test]
fn reads_relocated_salt_and_seed_with_equivalent_encodings() -> Result<()> {
    for base in [0x400000, 0x710000] {
        for alternate in [false, true] {
            let bytes = fixture(base, alternate);
            let pe = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
            let cancel = AtomicBool::new(false);
            assert_eq!(salts(&pe, &cancel)?, vec![&bytes[0x600..]]);
            assert_eq!(
                seeds(&pe, &cancel)?,
                [[0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x9a]]
            );
            assert!(matches!(
                salts(&pe, &AtomicBool::new(true)),
                Err(Error::Cancelled)
            ));
            assert!(matches!(
                seeds(&pe, &AtomicBool::new(true)),
                Err(Error::Cancelled)
            ));
        }
    }
    Ok(())
}
#[test]
fn rejects_unrelated_arguments_and_inconsistent_kdf_calls() -> Result<()> {
    for change in [0, 1, 2] {
        let mut bytes = fixture(0x400000, false);
        let instructions = Decoder::new(32, &bytes[0x300..0x400], DecoderOptions::NONE)
            .into_iter()
            .collect::<Vec<_>>();
        if change == 0 {
            let push = instructions
                .iter()
                .find(|i| i.mnemonic() == Mnemonic::Push && i.op0_kind() == OpKind::Immediate8to32)
                .ok_or(Error::InvalidFormat)?;
            bytes[0x300 + push.next_ip() as usize - 1] = 9;
        } else {
            let call = instructions
                .iter()
                .filter(|i| i.mnemonic() == Mnemonic::Call)
                .nth(1)
                .ok_or(Error::InvalidFormat)?;
            if change == 1 {
                bytes[0x300 + call.ip() as usize + 1] ^= 1;
            } else {
                bytes[0x300 + call.ip() as usize] = 0xc3;
            }
        }
        let pe = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
        assert!(seeds(&pe, &AtomicBool::new(false))?.is_empty());
    }
    Ok(())
}

#[test]
fn salt_assignment_allows_interleaved_global_pointer_load() -> Result<()> {
    let mut bytes = fixture(0x400000, false);
    // The optimizer loads the old filter object before assigning salt fields.
    let instructions = Decoder::new(32, &bytes[0x200..0x300], DecoderOptions::NONE)
        .into_iter()
        .collect::<Vec<_>>();
    let pointer = instructions
        .iter()
        .find(|i| constant_store(i))
        .ok_or(Error::InvalidFormat)?;
    let at = 0x200 + pointer.ip() as usize;
    bytes.copy_within(at..at + 21, at + 6);
    bytes[at..at + 2].copy_from_slice(&[0x8b, 0x35]);
    BinaryWriter::u32_le(0x401300, &mut bytes[at + 2..]);
    // Preserve the branch's original guarded extent after instruction insertion.
    BinaryWriter::u32_le(26, &mut bytes[0x209..]);
    let pe = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
    assert_eq!(salts(&pe, &AtomicBool::new(false))?, vec![&bytes[0x600..]]);
    // A flag-changing instruction must not be skipped as a harmless load.
    bytes[at] = 0x33;
    let pe = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
    assert!(salts(&pe, &AtomicBool::new(false))?.is_empty());
    Ok(())
}

fn configured_fixture(base: u32, alternate: bool) -> Vec<u8> {
    let mut bytes = fixture(base, alternate);
    let marker = super::super::wide_bytes("--xopt--no\0\0");
    bytes[0x400..0x418].copy_from_slice(&marker);
    bytes[0x418..0x420].copy_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
    bytes[0x450..0x454].fill(0);
    let mut code = vec![0x66, 0x8b, 0x0d];
    word(&mut code, base + 0x1204);
    let register = if alternate { 7 } else { 6 };
    code.push(0xb8 + register);
    word(&mut code, base + 0x1218);
    if alternate {
        code.extend([0x66, 0x81, 0xf9, b'x', 0]);
    } else {
        code.extend([0x66, 0x83, 0xf9, b'x']);
    }
    code.extend([0x0f, 0x45, 5 + register * 8]);
    word(&mut code, base + 0x1250);
    code.extend([0x89, 5 + register * 8]);
    word(&mut code, base + 0x1250);
    code.push(0xc3);
    bytes[0x380..0x380 + code.len()].copy_from_slice(&code);
    bytes
}

#[test]
fn active_xopt_seed_overrides_kdf_default_with_relocated_operands() -> Result<()> {
    for base in [0x400000, 0x710000] {
        for alternate in [false, true] {
            let mut bytes = configured_fixture(base, alternate);
            let pe = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
            let cancel = AtomicBool::new(false);
            assert_eq!(seeds(&pe, &cancel)?, [[8, 7, 6, 5, 4, 3, 2, 1]]);
            // A disabled selector leaves the null pointer and uses the KDF default.
            bytes[0x404] = b'-';
            let pe = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
            assert_eq!(
                seeds(&pe, &cancel)?,
                [[0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x9a]]
            );
            // The record alone does not prove that a seed is selected.
            bytes[0x404] = b'x';
            bytes[0x380..0x3c0].fill(0);
            let pe = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
            assert_eq!(
                seeds(&pe, &cancel)?,
                [[0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x9a]]
            );
        }
    }
    Ok(())
}

#[test]
fn seed_selector_uses_its_operand_instead_of_record_spelling() -> Result<()> {
    let mut bytes = configured_fixture(0x400000, false);
    bytes[0x400] = b'+';
    bytes[0x410] = b'y';
    let pe = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
    assert_eq!(
        seeds(&pe, &AtomicBool::new(false))?,
        [[8, 7, 6, 5, 4, 3, 2, 1]]
    );
    Ok(())
}

#[test]
fn configured_seed_truncation_and_unresolved_cache_do_not_use_default() -> Result<()> {
    let mut bytes = configured_fixture(0x400000, false);
    BinaryWriter::u32_le(1, &mut bytes[0x450..]);
    let pe = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
    assert!(matches!(
        seeds(&pe, &AtomicBool::new(false)),
        Err(Error::UnknownScheme(_))
    ));
    bytes[0x450..0x454].fill(0);
    bytes.truncate(0x41c);
    BinaryWriter::u32_le(0x21c, &mut bytes[0x188..]);
    let pe = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
    assert!(
        matches!(seeds(&pe, &AtomicBool::new(false)), Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof)
    );
    Ok(())
}

#[test]
fn conflicting_active_seeds_remain_ambiguous() -> Result<()> {
    let mut bytes = configured_fixture(0x400000, false);
    bytes.copy_within(0x380..0x3c0, 0x480);
    bytes.copy_within(0x400..0x420, 0x500);
    BinaryWriter::u32_le(0x401304, &mut bytes[0x483..]);
    BinaryWriter::u32_le(0x401318, &mut bytes[0x488..]);
    bytes[0x518] = 9;
    let pe = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
    assert!(matches!(
        super::super::archive_seed(&pe, &AtomicBool::new(false)),
        Err(Error::UnknownScheme(_))
    ));
    Ok(())
}
