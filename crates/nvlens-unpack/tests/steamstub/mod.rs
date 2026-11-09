#![allow(clippy::unwrap_used)]

use super::*;
use ::aes::{
    Aes256,
    cipher::{BlockEncrypt, KeyInit},
};
use nvlens_io::BinaryWriter;

const ENTRY: &[u8] = &[
    0xe8, 0, 0, 0, 0, 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55, 0x8b, 0x44, 0x24, 0x1c, 0x2d, 5, 0,
    0, 0, 0x8b, 0xcc, 0x83, 0xe4, 0xf0, 0x51, 0x51, 0x51, 0x50,
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
