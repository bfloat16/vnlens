use super::*;
use vnlens_io::BinaryWriter;

fn word(out: &mut Vec<u8>, value: u32) {
    let at = out.len();
    out.resize(at + 4, 0);
    BinaryWriter::u32_le(value, &mut out[at..]);
}
fn xor_loop(table: u32, add: bool) -> Vec<u8> {
    let mut code = vec![0x25]; // AND EAX,255; MOVZX ECX,[EAX+table]; XOR [EDI],CL.
    word(&mut code, 255);
    code.extend([0x0f, 0xb6, 0x88]);
    word(&mut code, table);
    code.extend([0x30, 0x0f]);
    if add {
        code.extend([0x83, 0xc2, 1, 0x83, 0xc7, 1]);
    } else {
        code.extend([0x42, 0x47]);
    }
    code.extend([0x3b, 0xd6, 0x7c]);
    code.push((-(code.len() as i32 + 1)) as u8);
    code.push(0xc3);
    code
}
fn fixture(base: u32, add: bool) -> Vec<u8> {
    let mut bytes = vec![0; 0x1800];
    bytes[..2].copy_from_slice(b"MZ");
    BinaryWriter::u32_le(0x80, &mut bytes[0x3c..]);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    for (at, value) in [(0x84, 0x14c), (0x86, 1), (0x94, 0xe0), (0x98, 0x10b)] {
        BinaryWriter::u16_le(value, &mut bytes[at..]);
    }
    for (at, value) in [
        (0xb4, base),
        (0xd4, 0x200),
        (0x184, 0x1000),
        (0x188, 0x1600),
        (0x18c, 0x200),
        (0x19c, 0x20000000),
    ] {
        BinaryWriter::u32_le(value, &mut bytes[at..]);
    }
    let code = xor_loop(base + 0x2000, add);
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    let mut code = vec![0x8d, 0x86]; // Guarded key application.
    word(&mut code, (-0x100i32) as u32);
    code.push(0x3d);
    word(&mut code, 0x100);
    code.extend([0x77, 13, 0x25]);
    word(&mut code, 0x8000000f);
    code.extend([0x8b, 0x0d]);
    word(&mut code, base + 0x2100);
    code.extend([0x8b, 0x09, 0xc3]);
    bytes[0x400..0x400 + code.len()].copy_from_slice(&code);
    let mut code = Vec::new();
    for index in 0..16 {
        code.push(0xa1);
        word(&mut code, base + 0x2100);
        code.extend([0x8b, 0x00, 0x0f, 0xb6, 0x0d]);
        word(&mut code, base + 0x2200 + index);
        code.extend([0x88, 0x48, index as u8, 0xc3]);
    }
    bytes[0x500..0x500 + code.len()].copy_from_slice(&code);
    bytes[0x1200..0x1300].fill(0x5a);
    bytes[0x1400..0x1410].copy_from_slice(&[0x33; 16]);
    let marker = b"RealLive SAVEDATA\0SEEN.TXT\0";
    bytes[0x1600..0x1600 + marker.len()].copy_from_slice(marker);
    bytes
}

#[test]
fn relocated_loops_and_scattered_key_assignments() -> Result<()> {
    for base in [0x400000, 0x710000] {
        for add in [false, true] {
            let bytes = fixture(base, add);
            let image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
            assert!(super::super::pe(&image)?);
            let options = parameters(&image, &AtomicBool::new(false))?;
            assert_eq!(options.keys["reallive_xor"].bytes(), &[0x5a; 256]);
            assert_eq!(options.keys["reallive_key1"].bytes(), &[0x33; 16]);
            assert!(matches!(
                parameters(&image, &AtomicBool::new(true)),
                Err(Error::Cancelled)
            ));
        }
    }
    Ok(())
}

#[test]
fn missing_ambiguous_and_incomplete_parameters_are_errors() -> Result<()> {
    let cancel = AtomicBool::new(false);
    for change in 0..3 {
        let mut bytes = fixture(0x400000, false);
        match change {
            0 => bytes[0x200..0x240].fill(0),
            1 => {
                let code = xor_loop(0x402300, false);
                bytes[0x300..0x300 + code.len()].copy_from_slice(&code);
                bytes[0x1500..0x1600].fill(0x6b);
            }
            _ => bytes[0x500 + 15 * 18..0x500 + 16 * 18].fill(0),
        }
        let image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
        assert!(matches!(
            parameters(&image, &cancel),
            Err(Error::UnknownScheme(_))
        ));
    }
    let mut bytes = fixture(0x400000, false);
    bytes[0x1600..0x1620].fill(0);
    let image = PeImage::parse(&bytes)?.ok_or(Error::InvalidFormat)?;
    assert!(!super::super::pe(&image)?);
    Ok(())
}

#[test]
fn pe_identity_precedes_layout_and_parameter_failure_stops_identification() -> Result<()> {
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(std::io::Error::other)?
        .as_nanos();
    let directory =
        Temp(std::env::temp_dir().join(format!("vnlens-reallive-{}-{stamp}", std::process::id())));
    std::fs::create_dir(&directory.0)?;
    let cancel = AtomicBool::new(false);
    std::fs::write(directory.0.join("Seen.txt"), b"RealLive SAVEDATA SEEN.TXT")?;
    assert!(crate::identify(&directory.0, &cancel)?.is_none());
    std::fs::write(directory.0.join("renamed.exe"), fixture(0x400000, false))?;
    let game = crate::identify(&directory.0, &cancel)?.ok_or(Error::InvalidFormat)?;
    assert_eq!(game.engine, crate::Engine::RealLive);
    assert!(game.evidence.starts_with("PE features"));
    let mut bytes = fixture(0x710000, true);
    bytes[0x1200..0x1300].fill(0x6b);
    std::fs::write(directory.0.join("other.exe"), bytes)?;
    assert!(matches!(
        crate::identify(&directory.0, &cancel),
        Err(Error::UnknownScheme(_))
    ));
    std::fs::remove_file(directory.0.join("other.exe"))?;
    let mut bytes = fixture(0x400000, false);
    bytes[0x200..0x240].fill(0);
    std::fs::write(directory.0.join("renamed.exe"), bytes)?;
    assert!(matches!(
        crate::identify(&directory.0, &cancel),
        Err(Error::UnknownScheme(_))
    ));
    Ok(())
}
