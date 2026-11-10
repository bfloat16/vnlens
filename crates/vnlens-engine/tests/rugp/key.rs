#![allow(clippy::unwrap_used)]

use super::*;
use vnlens_io::BinaryWriter;

fn fixture(base: u32, conflict: bool) -> Vec<u8> {
    let mut b = vec![0; 0x500];
    b[..2].copy_from_slice(b"MZ");
    BinaryWriter::u32_le(0x80, &mut b[0x3c..]);
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    BinaryWriter::u16_le(0x14c, &mut b[0x84..]);
    BinaryWriter::u16_le(2, &mut b[0x86..]);
    BinaryWriter::u16_le(0xe0, &mut b[0x94..]);
    BinaryWriter::u16_le(0x10b, &mut b[0x98..]);
    for (at, value) in [
        (0xb4, base),
        (0xd4, 0x200),
        (0x180, 0x100),
        (0x184, 0x1000),
        (0x188, 0x100),
        (0x18c, 0x200),
        (0x19c, 0x60000020),
        (0x1a8, 0x200),
        (0x1ac, 0x2000),
        (0x1b0, 0x200),
        (0x1b4, 0x300),
        (0x1c4, 0xc0000040),
        (0x300, base + 0x2080),
        (0x304, base + 0x2020),
        (0x308, 0x3002000c),
        (0x320, base + 0x2090),
        (0x324, base + 0x2060),
        (0x360, base + 0x20a0),
        (0x364, 4),
        (0x368, 0x96000000),
    ] {
        BinaryWriter::u32_le(value, &mut b[at..]);
    }
    b[0x380..0x388].copy_from_slice(b"OM_Test\0");
    b[0x390..0x396].copy_from_slice(b"value\0");
    b[0x3a0..0x3a4].copy_from_slice(b"int\0");
    let mut cursor = 0x200;
    for (address, value) in [(base + 0x2028, 8), (base + 0x2034, 0xffff0000)]
        .into_iter()
        .chain(conflict.then_some((base + 0x2028, 12)))
    {
        b[cursor..cursor + 2].copy_from_slice(&[0xc7, 0x05]);
        BinaryWriter::u32_le(address, &mut b[cursor + 2..]);
        BinaryWriter::u32_le(value, &mut b[cursor + 6..]);
        cursor += 10;
    }
    b[cursor] = 0xc3;
    b
}

#[test]
fn static_descriptors_follow_decoded_initializers_and_reject_conflicts() -> Result<()> {
    for base in [0x400000, 0x630000] {
        for conflict in [false, true] {
            let bytes = fixture(base, conflict);
            let image = PeImage::parse(&bytes)?.unwrap();
            let images = [image];
            let mut tables = Tables {
                images: &images,
                stores: BTreeMap::new(),
                imports: BTreeMap::new(),
            };
            tables.initialize(0, &AtomicBool::new(false))?;
            let fields = tables.fields(Pointer {
                module: 0,
                address: u64::from(base) + 0x2000,
            });
            if conflict {
                assert!(fields.is_none());
            } else {
                let fields = fields.unwrap();
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0]["name"], "value");
                assert_eq!(fields[0]["size"], 4);
            }
        }
    }
    let bytes = fixture(0x400000, false);
    let images = [PeImage::parse(&bytes)?.unwrap()];
    let mut tables = Tables {
        images: &images,
        stores: BTreeMap::new(),
        imports: BTreeMap::new(),
    };
    assert!(matches!(
        tables.initialize(0, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    Ok(())
}
