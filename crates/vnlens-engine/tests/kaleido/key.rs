use super::*;
use vnlens_io::BinaryWriter;
fn fixture(key: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 0x200 + 0x400 + key.len() + 1];
    bytes[..2].copy_from_slice(b"MZ");
    BinaryWriter::u32_le(0x80, &mut bytes[0x3c..]);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    BinaryWriter::u16_le(0x8664, &mut bytes[0x84..]);
    BinaryWriter::u16_le(1, &mut bytes[0x86..]);
    BinaryWriter::u16_le(0xf0, &mut bytes[0x94..]);
    BinaryWriter::u16_le(0x20b, &mut bytes[0x98..]);
    BinaryWriter::u64_le(0x140000000, &mut bytes[0xb0..]);
    BinaryWriter::u32_le(0x200, &mut bytes[0xd4..]);
    let size = bytes.len() - 0x200;
    bytes[0x188..0x18d].copy_from_slice(b".text");
    for (at, value) in [
        (0x190, size as u32),
        (0x194, 0x1000),
        (0x198, size as u32),
        (0x19c, 0x200),
        (0x1ac, 0x60000020),
    ] {
        BinaryWriter::u32_le(value, &mut bytes[at..]);
    }
    let code = &mut bytes[0x200..];
    code[..7].copy_from_slice(&[0x48, 0x8d, 0x15, 0, 0, 0, 0]);
    BinaryWriter::u32_le(0x400 - 7, &mut code[3..]);
    code[7..12].copy_from_slice(&[0x48, 0x8d, 0x4c, 0x24, 0x40]);
    code[12] = 0xe8;
    BinaryWriter::u32_le(0x80 - 17, &mut code[13..]);
    code[17] = 0xba;
    BinaryWriter::u32_le(131, &mut code[18..]);
    code[22..27].copy_from_slice(&[0x48, 0x8d, 0x4c, 0x24, 0x40]);
    code[27] = 0xe8;
    BinaryWriter::u32_le(0x100 - 32, &mut code[28..]);
    code[32] = 0xc3;
    code[0x80] = 0xc3;
    let setter = [
        0x48, 0x8d, 0x05, 0, 0, 0, 0, 0x8b, 0xda, 0x48, 0x83, 0x79, 0x18, 0x0f, 0x4c, 0x8b, 0x41,
        0x10, 0xe8, 0, 0, 0, 0, 0x89, 0x1d, 0, 0, 0, 0, 0xc3,
    ];
    code[0x100..0x100 + setter.len()].copy_from_slice(&setter);
    BinaryWriter::u32_le(0x300 - 0x107, &mut code[0x103..]);
    BinaryWriter::u32_le((0x80i32 - 0x117) as u32, &mut code[0x113..]);
    BinaryWriter::u32_le(0x320 - 0x11d, &mut code[0x119..]);
    code[0x400..0x400 + key.len()].copy_from_slice(key);
    bytes
}
#[test]
fn decoded_call_chain_recovers_parameters_and_checks_setter() -> Result<()> {
    for key in [b"fixture-secret".to_vec(), vec![b'k'; 400]] {
        let mut bytes = fixture(&key);
        let image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
        assert_eq!(
            parameters(&image, &AtomicBool::new(false))?,
            vec![(key, 131)]
        );
        assert!(matches!(
            parameters(&image, &AtomicBool::new(true)),
            Err(Error::Cancelled)
        ));
        bytes[0x200 + 0x100 + 0x11] = 0x11;
        let image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
        assert!(parameters(&image, &AtomicBool::new(false))?.is_empty());
    }
    Ok(())
}

#[test]
fn movie_call_uses_its_own_key_and_4096_byte_period() -> Result<()> {
    let mut bytes = fixture(b"synthetic-movie");
    let code = &mut bytes[0x200..];
    code[33..0x100].fill(0x90);
    code[0x80] = 0xc3;
    let callsite = [
        0x4d, 0x8d, 0x4d, 0x30, 0x41, 0xb8, 0, 0, 0, 0, 0x48, 0x8d, 0x15, 0, 0, 0, 0, 0x49, 0x8b,
        0xcf, 0xe8, 0, 0, 0, 0, 0xc3,
    ];
    code[0x50..0x50 + callsite.len()].copy_from_slice(&callsite);
    BinaryWriter::u32_le(4096, &mut code[0x56..]);
    BinaryWriter::u32_le(0x400 - 0x61, &mut code[0x5d..]);
    BinaryWriter::u32_le(0x200 - 0x69, &mut code[0x65..]);
    for (i, constant) in [19_650_218, 1_812_433_253, 1_664_525, 1_566_083_941]
        .into_iter()
        .enumerate()
    {
        let at = 0x200 + i * 5;
        code[at] = 0xb8;
        BinaryWriter::u32_le(constant, &mut code[at + 1..]);
    }
    code[0x214] = 0xc3;
    let image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
    assert_eq!(
        movie_parameters(&image, &AtomicBool::new(false))?,
        Some(b"synthetic-movie".to_vec())
    );
    bytes[0x200 + 0x56] = 131;
    let image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
    assert!(movie_parameters(&image, &AtomicBool::new(false))?.is_none());
    Ok(())
}
