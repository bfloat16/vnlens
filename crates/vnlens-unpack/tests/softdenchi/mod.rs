use super::*;
use vnlens_io::BinaryWriter;

fn executable(base: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 0x800];
    bytes[..2].copy_from_slice(b"MZ");
    BinaryWriter::u32_le(0x80, &mut bytes[0x3c..]);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    for (at, value) in [(0x84, 0x14c), (0x86, 1), (0x94, 0xe0), (0x98, 0x10b)] {
        BinaryWriter::u16_le(value, &mut bytes[at..]);
    }
    for (at, value) in [
        (0xa8, 0x1000),
        (0xb4, base),
        (0xd0, 0x2000),
        (0xd4, 0x200),
        (0x180, 0x600),
        (0x184, 0x1000),
        (0x188, 0x600),
        (0x18c, 0x200),
        (0x19c, 0x6000_0020),
    ] {
        BinaryWriter::u32_le(value, &mut bytes[at..]);
    }
    bytes[0x178..0x180].copy_from_slice(b".text\0\0\0");
    bytes[0x200..0x200 + payload.len()].copy_from_slice(payload);
    bytes
}

#[test]
fn selects_second_pe_past_sections_and_metadata_without_copying() -> Result<()> {
    let host = executable(0x710000, b"host data");
    let mut bytes = executable(0x400000, b"Software\\softdenchi\0");
    // A complete PE inside a wrapper section must not replace the host.
    bytes[0x300..0x500].copy_from_slice(&host[..0x200]);
    bytes.extend_from_slice(b"metadata MZ without a PE header");
    let offset = bytes.len();
    bytes.extend_from_slice(&host);
    bytes.extend_from_slice(b"host overlay");
    bytes.extend_from_slice(&executable(0x810000, b"third PE"));
    let mut image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
    assert!(unpack(&mut image, &AtomicBool::new(false))?);
    assert_eq!(image.image_base, 0x710000);
    assert_eq!(image.read(0x1000, 9)?, b"host data");
    assert!(std::ptr::eq(
        image.file_bytes().as_ptr(),
        bytes[offset..].as_ptr()
    ));
    assert_eq!(image.file_bytes(), &bytes[offset..]);
    assert!(!unpack(&mut image, &AtomicBool::new(false))?);
    Ok(())
}

#[test]
fn unmarked_appended_pe_and_cancelled_wrapper_are_unchanged() -> Result<()> {
    let mut bytes = executable(0x400000, b"ordinary executable");
    bytes.extend_from_slice(&executable(0x710000, b"SoftDenchi"));
    let mut image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
    assert!(!unpack(&mut image, &AtomicBool::new(false))?);
    assert_eq!(image.image_base, 0x400000);
    assert!(std::ptr::eq(image.file_bytes().as_ptr(), bytes.as_ptr()));
    bytes[0x200..0x20a].copy_from_slice(b"SoftDenchi");
    let mut image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
    assert!(matches!(
        unpack(&mut image, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    assert_eq!(image.image_base, 0x400000);
    Ok(())
}

#[test]
fn missing_and_truncated_hosts_are_errors_without_fallback() -> Result<()> {
    let wrapper = executable(0x400000, b"SoftDenchi");
    let mut image = PeImage::parse(&wrapper)?.ok_or(Error::InvalidFormat)?;
    assert!(matches!(
        unpack(&mut image, &AtomicBool::new(false)),
        Err(Error::Corrupt { .. })
    ));
    let host = executable(0x710000, b"host");
    for size in [0x84, 0x178, 0x7ff] {
        let mut bytes = wrapper.clone();
        bytes.extend_from_slice(&host[..size]);
        let mut image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
        assert!(matches!(unpack(&mut image, &AtomicBool::new(false)),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof));
        assert_eq!(image.image_base, 0x400000);
    }
    Ok(())
}
