#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn snappy_dependency_requires_native_exports_and_does_not_replace_yszlb() -> Result<()> {
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let root = Temp(std::env::temp_dir().join(format!(
            "vnlens-yuris-codec-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(std::io::Error::other)?
                .as_nanos()
        )));
    std::fs::create_dir_all(root.0.join("pac"))?;
    std::fs::write(root.0.join("yscfg.dat"), [])?;
    std::fs::write(root.0.join("pac/bn.ypf"), b"YPF\0")?;
    let mut dll = executable(0x10000000);
    dll[0x200..0x247].fill(0);
    BinaryWriter::u32_le(16, &mut dll[0xf4..]);
    BinaryWriter::u32_le(0x1300, &mut dll[0xf8..]);
    BinaryWriter::u32_le(0x40, &mut dll[0xfc..]);
    for (at, value) in [
        (0x510, 1),
        (0x514, 1),
        (0x518, 1),
        (0x51c, 0x1340),
        (0x520, 0x1344),
        (0x524, 0x1348),
        (0x540, 0x1000),
        (0x544, 0x1360),
    ] {
        BinaryWriter::u32_le(value, &mut dll[at..]);
    }
    dll[0x560..0x571].copy_from_slice(b"YSSnp_Uncompress\0");
    let marker = b".?AVByteArraySource@snappy@@\0";
    dll[0x580..0x580 + marker.len()].copy_from_slice(marker);
    std::fs::write(root.0.join("YSSnp.dll"), &dll)?;
    let cancel = AtomicBool::new(false);
    let identify = || crate::identify(&root.0, &cancel)?.ok_or(Error::InvalidFormat);
    assert_eq!(
        identify()?.resource_options().numbers.get("ypf_snappy"),
        Some(&1)
    );
    std::fs::write(root.0.join("YSZLB.DLL"), [])?;
    assert!(
        !identify()?
            .resource_options()
            .numbers
            .contains_key("ypf_snappy")
    );
    std::fs::remove_file(root.0.join("YSZLB.DLL"))?;
    let mut exe = executable(0x400000);
    let evidence = b"ysbin\\yst%05d.ybn\0ysbin\\yst_list.ybn\0YSZLB.DLL\0";
    exe[0x500..0x500 + evidence.len()].copy_from_slice(evidence);
    std::fs::write(root.0.join("game.exe"), exe)?;
    assert!(
        !identify()?
            .resource_options()
            .numbers
            .contains_key("ypf_snappy")
    );
    std::fs::remove_file(root.0.join("game.exe"))?;
    dll[0x560] = b'X';
    std::fs::write(root.0.join("YSSnp.dll"), dll)?;
    assert!(
        !identify()?
            .resource_options()
            .numbers
            .contains_key("ypf_snappy")
    );
    Ok(())
}

fn from_pe(bytes: &[u8], cancel: &AtomicBool) -> Result<Option<Secret>> {
    let Some(mut pe) = PeImage::parse(bytes)? else {
        return Ok(None);
    };
    vnlens_unpack::steamstub::unpack(&mut pe, cancel)?;
    from_image(&pe, cancel)
}

fn executable(base: u32) -> Vec<u8> {
    let mut b = vec![0; 0x600];
    b[..2].copy_from_slice(b"MZ");
    BinaryWriter::u32_le(0x80, &mut b[0x3c..]);
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    BinaryWriter::u16_le(0x14c, &mut b[0x84..]);
    BinaryWriter::u16_le(1, &mut b[0x86..]);
    BinaryWriter::u16_le(0xe0, &mut b[0x94..]);
    BinaryWriter::u16_le(0x10b, &mut b[0x98..]);
    BinaryWriter::u32_le(base, &mut b[0xb4..]);
    BinaryWriter::u32_le(0x200, &mut b[0xd4..]);
    BinaryWriter::u32_le(0x1000, &mut b[0x184..]);
    BinaryWriter::u32_le(0x400, &mut b[0x188..]);
    BinaryWriter::u32_le(0x200, &mut b[0x18c..]);
    BinaryWriter::u32_le(0x2000_0000, &mut b[0x19c..]);
    let signature = &mut b[0x200..0x247];
    signature[..2].copy_from_slice(&[0x8b, 0x3d]);
    signature[6..29].copy_from_slice(&[
        0x33, 0xc0, 0x8a, 0x37, 0x8b, 0xcf, 0x84, 0xf6, 0x74, 8, 0x41, 0x40, 0x8a, 0x11, 0x84,
        0xd2, 0x75, 0xf8, 0x8b, 0xd0, 0x8b, 0xc7, 0xe8,
    ]);
    signature[33..40].copy_from_slice(&[0x8b, 0xd0, 0xc1, 0xea, 0x18, 0x88, 0x15]);
    signature[44..51].copy_from_slice(&[0x8b, 0xc8, 0xc1, 0xe9, 0x10, 0x88, 0x0d]);
    signature[55..62].copy_from_slice(&[0x8b, 0xd0, 0xc1, 0xea, 8, 0x88, 0x15]);
    signature[66] = 0xa2;
    BinaryWriter::u32_le(base + 0x1100, &mut signature[2..]);
    for (offset, index) in [(40, 0), (51, 1), (62, 2), (67, 3)] {
        BinaryWriter::u32_le(base + 0x4000 + index, &mut signature[offset..]);
    }
    BinaryWriter::u32_le(base + 0x1120, &mut b[0x300..]);
    b[0x320..0x32a].copy_from_slice(b"123456789\0");
    b
}

#[test]
fn scans_relocated_pe_without_game_name_or_fixed_key() {
    for base in [0x400000, 0x10000000] {
        let bytes = executable(base);
        let key = from_pe(&bytes, &AtomicBool::new(false)).unwrap().unwrap();
        assert_eq!(key.bytes(), [0xcb, 0xf4, 0x39, 0x26]);
        let mut data = vec![0; 7];
        vnlens_crypto::cipher::xor::apply_u32_key(&mut data, key.bytes().try_into().unwrap());
        assert_eq!(data, [0xcb, 0xf4, 0x39, 0x26, 0xcb, 0xf4, 0x39]);
        vnlens_crypto::cipher::xor::apply_u32_key(&mut data, key.bytes().try_into().unwrap());
        assert_eq!(data, [0; 7]);
        for end in 0..bytes.len() {
            let _ = from_pe(&bytes[..end], &AtomicBool::new(false));
        }
    }
    let mut bytes = executable(0x400000);
    bytes[0x200 + 33] = 0;
    assert!(from_pe(&bytes, &AtomicBool::new(false)).unwrap().is_none());
}

#[test]
fn equivalent_mov_encodings_preserve_initialization_dataflow() {
    let mut bytes = executable(0x400000);
    // MOV EAX,EDI: both opcode directions have the same operands.
    bytes[0x21a..0x21c].copy_from_slice(&[0x89, 0xf8]);
    // MOV [absolute],AL: generic ModRM instead of the accumulator form.
    let address = BinaryReader::u32_le(&bytes[0x243..]);
    bytes[0x242..0x244].copy_from_slice(&[0x88, 5]);
    BinaryWriter::u32_le(address, &mut bytes[0x244..]);
    assert_eq!(
        from_pe(&bytes, &AtomicBool::new(false))
            .unwrap()
            .unwrap()
            .bytes(),
        [0xcb, 0xf4, 0x39, 0x26]
    );
    assert!(matches!(
        from_pe(&bytes, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    // A branch to the middle of a load is not the string-length loop.
    bytes[0x20f] = 7;
    assert!(from_pe(&bytes, &AtomicBool::new(false)).unwrap().is_none());
}

#[test]
fn unreadable_pe_resources_require_independent_engine_evidence() {
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = Temp(std::env::temp_dir().join(format!(
        "vnlens-yuris-resource-{}-{timestamp}",
        std::process::id()
    )));
    std::fs::create_dir_all(root.0.join("pac")).unwrap();
    let mut bytes = vec![0; 0x300];
    bytes[..2].copy_from_slice(b"MZ");
    BinaryWriter::u32_le(0x80, &mut bytes[0x3c..]);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    BinaryWriter::u16_le(0x14c, &mut bytes[0x84..]);
    BinaryWriter::u16_le(1, &mut bytes[0x86..]);
    BinaryWriter::u16_le(0xe0, &mut bytes[0x94..]);
    BinaryWriter::u16_le(0x10b, &mut bytes[0x98..]);
    BinaryWriter::u32_le(0x400000, &mut bytes[0xb4..]);
    BinaryWriter::u32_le(0x200, &mut bytes[0xd4..]);
    BinaryWriter::u32_le(16, &mut bytes[0xf4..]);
    // A loader may replace this resource directory at runtime. Its disk RVA
    // is not mapped, so it cannot provide static PE identification evidence.
    BinaryWriter::u32_le(0x8000, &mut bytes[0x108..]);
    BinaryWriter::u32_le(0x100, &mut bytes[0x10c..]);
    BinaryWriter::u32_le(0x1000, &mut bytes[0x184..]);
    BinaryWriter::u32_le(0x100, &mut bytes[0x188..]);
    BinaryWriter::u32_le(0x200, &mut bytes[0x18c..]);
    BinaryWriter::u32_le(0x2000_0000, &mut bytes[0x19c..]);
    std::fs::write(root.0.join("protected.exe"), bytes).unwrap();
    std::fs::write(root.0.join("pac/bn.ypf"), b"YPF\0").unwrap();
    let cancel = AtomicBool::new(false);
    assert!(
        matches!(crate::identify(&root.0, &cancel), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof)
    );
    std::fs::write(root.0.join("yscfg.dat"), []).unwrap();
    let identified = crate::identify(&root.0, &cancel).unwrap().unwrap();
    assert_eq!(identified.engine, crate::Engine::Yuris);
    assert_eq!(identified.evidence, "Game directory layout");
    assert!(identified.resource_options().keys.is_empty());
    assert!(!root.0.join("yssfs.dat").exists());
    // Directory evidence never requires parsing the archive to identify a host.
    std::fs::write(root.0.join("pac/bn.ypf"), b"broken").unwrap();
    assert_eq!(
        crate::identify(&root.0, &cancel).unwrap().unwrap().engine,
        crate::Engine::Yuris
    );
    std::fs::remove_file(root.0.join("pac/bn.ypf")).unwrap();
    assert!(
        matches!(crate::identify(&root.0, &cancel), Err(Error::Io(error))
        if error.kind() == std::io::ErrorKind::UnexpectedEof)
    );
}

#[test]
fn identified_yuris_pe_without_a_key_defers_to_resource_recovery() {
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = Temp(std::env::temp_dir().join(format!(
        "vnlens-yuris-key-order-{}-{timestamp}",
        std::process::id()
    )));
    std::fs::create_dir(&root.0).unwrap();
    let mut bytes = executable(0x400000);
    bytes[0x200..0x247].fill(0);
    let markers = b"ysbin\\yst%05d.ybn\0ysbin\\yst_list.ybn\0";
    bytes[0x500..0x500 + markers.len()].copy_from_slice(markers);
    std::fs::write(root.0.join("game.exe"), bytes).unwrap();
    let identified = crate::identify(&root.0, &AtomicBool::new(false))
        .unwrap()
        .unwrap();
    assert_eq!(identified.engine, crate::Engine::Yuris);
    assert!(identified.resource_options().keys.is_empty());
    assert!(identified.evidence.starts_with("PE features"));
    assert!(!root.0.join("yscfg.dat").exists());
}
