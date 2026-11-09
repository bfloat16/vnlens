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
fn loader_code(base: u32, scene: Option<u8>, wide: bool, alternate: bool, gap: &[u8]) -> Vec<u8> {
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
fn scheduled_fixture(inside: &[u8], between: &[u8]) -> Vec<u8> {
    let base = 0x610000;
    let mut bytes = fixture(base, 2, false, false, &[]);
    for (at, scene) in [(0x200, Some(2)), (0x600, None)] {
        let mut code = loader_code(base, scene, false, false, &[]);
        let start = if scene.is_some() { 0 } else { 10 };
        code.splice(start + 8..start + 8, between.iter().copied());
        code.splice(start + 5..start + 5, inside.iter().copied());
        if scene.is_none() {
            let target = nvlens_io::BinaryReader::u32_le(&code[6..]);
            BinaryWriter::u32_le(
                target + inside.len() as u32 + between.len() as u32,
                &mut code[6..],
            );
        }
        bytes[at..at + code.len()].copy_from_slice(&code);
    }
    bytes
}
#[test]
fn scheduled_key_setup_preserves_byte_copies_and_loader_guards() -> Result<()> {
    for (inside, between) in [
        // XOR ECX,ECX inside the first copy; MOV EDX,EDI before the next.
        (&[0x33, 0xc9][..], &[0x8b, 0xd7][..]),
        // A frame load and a different pointer/counter register allocation.
        (&[0x8b, 0x75, 0x08][..], &[0x33, 0xff, 0x8b, 0xde][..]),
    ] {
        let bytes = scheduled_fixture(inside, between);
        let image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
        let options = parameters(&image, &AtomicBool::new(false))?;
        assert_eq!(options.keys["siglus_game"].bytes(), &bytes[0x1200..0x1210]);
        assert_eq!(options.keys["siglus_scene"].bytes(), &bytes[0x1000..0x1100]);
        assert_eq!(
            options.keys["siglus_gameexe"].bytes(),
            &bytes[0x1100..0x1200]
        );
    }
    // Reject AL/EAX, frame/stack clobbers, memory writes and control flow
    // in either scheduling position; they cannot be skipped as setup.
    for invalid in [
        &[0x8b, 0xc7][..],
        &[0x33, 0xc0][..],
        &[0xb0, 0][..],
        &[0x8b, 0xef][..],
        &[0x8b, 0xe7][..],
        &[0xc6, 0x45, 0xef, 0][..],
        &[0xeb, 0][..],
        &[0xe8, 0, 0, 0, 0][..],
        &[0xc3][..],
    ] {
        for (inside, between) in [(invalid, &[][..]), (&[][..], invalid)] {
            let bytes = scheduled_fixture(inside, between);
            let image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
            assert!(matches!(
                parameters(&image, &AtomicBool::new(false)),
                Err(Error::UnknownScheme(_))
            ));
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
