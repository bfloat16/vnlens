#![allow(clippy::unwrap_used)]

use super::*;
use crate::BinaryWriter;

#[test]
fn imports_and_ordinal_exports_preserve_relocated_slots() -> io::Result<()> {
    for base in [0x400000, 0x710000] {
        let mut b = fixture(base);
        b[0x200..].fill(0);
        for (at, n) in [
            (0xf8, 0x1000),
            (0xfc, 0x60),
            (0x100, 0x1080),
            (0x104, 40),
            (0x210, 100),
            (0x214, 1),
            (0x21c, 0x1040),
            (0x240, 0x1100),
            (0x280, 0x10c0),
            (0x28c, 0x10b0),
            (0x290, 0x10d0),
            (0x2c0, 0x80000064),
        ] {
            BinaryWriter::u32_le(n, &mut b[at..]);
        }
        b[0x2b0..0x2b8].copy_from_slice(b"host.dll");
        let image = PeImage::parse(&b)?.unwrap();
        assert_eq!(image.export_ordinal(100)?, Some(u64::from(base) + 0x1100));
        assert!(image.export_ordinal(99)?.is_none());
        let imports = image.imports()?;
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].library, b"host.dll");
        assert!(matches!(imports[0].symbol, ImportSymbol::Ordinal(100)));
        assert_eq!(imports[0].slot, u64::from(base) + 0x10d0);
        BinaryWriter::u32_le(20, &mut b[0x104..]);
        assert_eq!(
            PeImage::parse(&b)?
                .unwrap()
                .imports()
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::UnexpectedEof)
        );
    }
    Ok(())
}
fn fixture(base: u32) -> Vec<u8> {
    let mut b = vec![0; 0x600];
    b[..2].copy_from_slice(b"MZ");
    BinaryWriter::u32_le(0x80, &mut b[0x3c..]);
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    BinaryWriter::u16_le(0x14c, &mut b[0x84..]);
    BinaryWriter::u16_le(1, &mut b[0x86..]);
    BinaryWriter::u16_le(0xe0, &mut b[0x94..]);
    BinaryWriter::u16_le(0x10b, &mut b[0x98..]);
    for (at, n) in [
        (0xb4, base),
        (0xd4, 0x200),
        (0xf4, 16),
        (0x108, 0x1000),
        (0x10c, 0x180),
        (0x184, 0x1000),
        (0x188, 0x400),
        (0x18c, 0x200),
        (0x210, 10),
        (0x214, 0x80000020),
        (0x230, 0x80000080),
        (0x234, 0x80000040),
        (0x250, 1033),
        (0x254, 0x60),
        (0x260, 0x1200),
        (0x264, 3),
    ] {
        BinaryWriter::u32_le(n, &mut b[at..]);
    }
    for at in [0x20e, 0x22c, 0x24e] {
        BinaryWriter::u16_le(1, &mut b[at..]);
    }
    let name = "STARTUP.TJS";
    BinaryWriter::u16_le(name.len() as u16, &mut b[0x280..]);
    for (i, w) in name.encode_utf16().enumerate() {
        BinaryWriter::u16_le(w, &mut b[0x282 + i * 2..]);
    }
    b[0x400..0x403].copy_from_slice(b"TJS");
    b
}
#[test]
fn resources_follow_named_paths_and_relocated_payload_rvas() -> io::Result<()> {
    for base in [0x400000, 0x610000] {
        let mut bytes = fixture(base);
        let image = PeImage::parse(&bytes)?.unwrap();
        assert_eq!(
            image.resource("#10", "STARTUP.TJS")?,
            Some(b"TJS".as_slice())
        );
        assert!(image.resource("#10", "BOOTSTRAP")?.is_none());
        BinaryWriter::u32_le(0x8000_0000, &mut bytes[0x254..]);
        assert!(
            PeImage::parse(&bytes)?
                .unwrap()
                .resource("#10", "STARTUP.TJS")
                .is_err()
        );
        BinaryWriter::u32_le(0x60, &mut bytes[0x254..]);
        BinaryWriter::u32_le(0x1400, &mut bytes[0x260..]);
        assert_eq!(
            PeImage::parse(&bytes)?
                .unwrap()
                .resource("#10", "STARTUP.TJS")
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    Ok(())
}

#[test]
fn exports_check_ordinals_forwarders_and_table_bounds() -> io::Result<()> {
    for base in [0x400000, 0x610000] {
        let mut bytes = fixture(base);
        for (at, value) in [
            (0xf8, 0x1100),
            (0xfc, 0x80),
            (0x314, 1),
            (0x318, 1),
            (0x31c, 0x1140),
            (0x320, 0x1144),
            (0x324, 0x1148),
            (0x340, 0x1200),
            (0x344, 0x1150),
        ] {
            BinaryWriter::u32_le(value, &mut bytes[at..]);
        }
        bytes[0x350..0x357].copy_from_slice(b"V2Link\0");
        let image = PeImage::parse(&bytes)?.unwrap();
        assert_eq!(image.export(b"V2Link")?, Some(u64::from(base) + 0x1200));
        assert_eq!(image.export(b"absent")?, None);
        BinaryWriter::u32_le(0x1160, &mut bytes[0x340..]);
        assert_eq!(PeImage::parse(&bytes)?.unwrap().export(b"V2Link")?, None);
        BinaryWriter::u16_le(1, &mut bytes[0x348..]);
        assert!(PeImage::parse(&bytes)?.unwrap().export(b"V2Link").is_err());
        BinaryWriter::u16_le(0, &mut bytes[0x348..]);
        BinaryWriter::u32_le(0x13ff, &mut bytes[0x320..]);
        assert_eq!(
            PeImage::parse(&bytes)?
                .unwrap()
                .export(b"V2Link")
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    Ok(())
}

#[test]
fn initial_words_include_only_the_declared_zero_filled_tail() -> io::Result<()> {
    let mut bytes = fixture(0x400000);
    BinaryWriter::u32_le(0x800, &mut bytes[0x180..]);
    bytes[0x5ff] = 0xab;
    let image = PeImage::parse(&bytes)?.unwrap();
    assert_eq!(image.u32_at_va(0x4013ff)?, 0xab);
    assert_eq!(image.u32_at_va(0x401400)?, 0);
    assert_eq!(
        image.u32_at_va(0x4017fd).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert_eq!(
        image.u32_at_va(u64::MAX).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    Ok(())
}
