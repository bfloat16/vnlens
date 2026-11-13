use super::*;
use std::{cell::Cell, sync::atomic::AtomicBool};
use vnlens_core::{ArchiveOptions, Secret};
use vnlens_io::BinaryWriter;

struct Companion {
    calls: Cell<usize>,
    bytes: Vec<u8>,
}
impl ResourceResolver for Companion {
    fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.calls.set(self.calls.get() + 1);
        Ok((name == "ysbin/ysc.ybn").then(|| self.bytes.clone()))
    }
}

fn sample() -> (Vec<u8>, Companion) {
    let mut data = vec![0; 32];
    data[..4].copy_from_slice(b"YSTB");
    for (offset, value) in [(4, 0x227), (8, 2), (12, 8), (16, 24), (20, 12), (24, 8)] {
        BinaryWriter::u32_le(value, &mut data[offset..]);
    }
    data.extend_from_slice(&[0, 1, 0, 0, 0, 1, 0, 0]);
    for offset in [4, 0] {
        let mut argument = [0; 12];
        BinaryWriter::u32_le(4, &mut argument[4..]);
        BinaryWriter::u32_le(offset, &mut argument[8..]);
        data.extend_from_slice(&argument);
    }
    data.extend_from_slice(b"abcdefghijkl");
    data.extend_from_slice(&[0; 8]);
    let mut bytes = vec![0; 16];
    bytes[..4].copy_from_slice(b"YSCM");
    BinaryWriter::u32_le(0x227, &mut bytes[4..]);
    BinaryWriter::u32_le(1, &mut bytes[8..]);
    bytes.extend_from_slice(b"WORD\0\0");
    (
        data,
        Companion {
            calls: Cell::new(0),
            bytes,
        },
    )
}

#[test]
fn pe_keys_are_used_without_reading_companions_or_replacing_the_key() -> Result<()> {
    let (plain, resources) = sample();
    let mut encrypted = plain.clone();
    let key = [0x12, 0x34, 0x56, 0x78];
    decrypt_ystb(&mut encrypted, &key)?;
    let mut options = ArchiveOptions::default();
    options.keys.insert("ystb", Secret::new(key));
    let cancel = AtomicBool::new(false);
    assert_eq!(
        &*crate::decode_with_resources_as(
            "ybn/yuris",
            &encrypted,
            Some(&resources),
            &options,
            &cancel
        )?,
        plain
    );
    assert_eq!(resources.calls.get(), 0);
    let wrong = [0xff; 4];
    options.keys.insert("ystb", Secret::new(wrong));
    let mut expected = encrypted.clone();
    decrypt_ystb(&mut expected, &wrong)?;
    assert_eq!(
        &*crate::decode_with_resources_as(
            "ybn/yuris",
            &encrypted,
            Some(&resources),
            &options,
            &cancel
        )?,
        expected
    );
    assert_eq!(resources.calls.get(), 0);
    assert_ne!(expected, plain);
    options.keys.insert("ystb", Secret::new([1, 2, 3]));
    assert!(
        crate::decode_with_resources_as(
            "ybn/yuris",
            &encrypted,
            Some(&resources),
            &options,
            &cancel
        )
        .is_err()
    );
    assert_eq!(resources.calls.get(), 0);
    Ok(())
}

#[test]
fn missing_pe_keys_use_structural_recovery_and_auxiliary_tables_are_unchanged() -> Result<()> {
    let (plain, resources) = sample();
    let mut encrypted = plain.clone();
    decrypt_ystb(&mut encrypted, &[0x12, 0x34, 0x56, 0x78])?;
    let options = ArchiveOptions::default();
    let cancel = AtomicBool::new(false);
    assert_eq!(
        &*crate::decode_with_resources_as(
            "ybn/yuris",
            &encrypted,
            Some(&resources),
            &options,
            &cancel
        )?,
        plain
    );
    assert_eq!(resources.calls.get(), 1);
    assert!(matches!(
        crate::decode_with_resources_as("ybn/yuris", &encrypted, None, &options, &cancel),
        Err(Error::UnknownScheme(_))
    ));
    assert!(matches!(
        crate::decode_with_resources_as(
            "ybn/yuris",
            &encrypted,
            Some(&resources),
            &options,
            &AtomicBool::new(true)
        ),
        Err(Error::Cancelled)
    ));
    assert_eq!(resources.calls.get(), 1);
    let mut options = options;
    options.keys.insert("ystb", Secret::new([0xff; 4]));
    assert!(matches!(
        crate::decode_with_resources_as(
            "ybn/yuris",
            &resources.bytes,
            Some(&resources),
            &options,
            &cancel
        )?,
        std::borrow::Cow::Borrowed(_)
    ));
    assert_eq!(resources.calls.get(), 1);
    Ok(())
}
