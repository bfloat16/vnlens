use super::*;
use crate::ir::{Operation, TextOperation, Value};
use vnlens_core::Secret;
use vnlens_io::BinaryWriter;

fn scene(code: &[u8], encrypted: bool) -> Result<(Vec<u8>, ArchiveOptions)> {
    let mut data = vec![0; 0x1d4];
    for (at, value) in [
        (0, 0x1d0),
        (4, if encrypted { 110002 } else { 10002 }),
        (8, 0x1d0),
        (12, 1),
        (16, 4),
        (20, 0x1d4),
        (24, 0),
        (28, 0),
        (32, 0x1d4),
        (36, code.len() as u32),
    ] {
        BinaryWriter::u32_le(value, &mut data[at..]);
    }
    BinaryWriter::u32_le(1000000, &mut data[0x1d0..]);
    let mut plain = code.to_vec();
    let mut options = ArchiveOptions::default();
    options
        .keys
        .insert("reallive_xor", Secret::new([0x5a; 256]));
    options
        .keys
        .insert("reallive_key1", Secret::new([0x33; 16]));
    if encrypted && plain.len() > 0x100 {
        let end = plain.len().min(0x201);
        vnlens_crypto::cipher::xor::apply(&mut plain[0x100..end], &[0x33; 16])
            .map_err(|e| Error::UnknownScheme(Some(e.to_string())))?;
    }
    let mut packed = vec![0; 8];
    BinaryWriter::u32_le(plain.len() as u32, &mut packed[4..]);
    for bytes in plain.chunks(8) {
        packed.push(0xff);
        packed.extend(bytes);
    }
    let length = packed.len() as u32;
    BinaryWriter::u32_le(length, &mut packed);
    vnlens_crypto::cipher::xor::apply(&mut packed, &[0x5a; 256])
        .map_err(|e| Error::UnknownScheme(Some(e.to_string())))?;
    BinaryWriter::u32_le(length, &mut data[40..]);
    data.extend(packed);
    Ok((data, options))
}

#[test]
fn keeps_header_text_memory_tokens_and_native_command_fields() -> Result<()> {
    let mut code = vec![b'@', 0, 0, b'\n', 7, 0];
    code.extend(b"\"hello\"");
    code.extend([
        b'#', 1, 13, 0, 0, 1, 0, 0, b'(', b'$', 0xff, 42, 0, 0, 0, b')',
    ]);
    let (data, options) = scene(&code, false)?;
    let script = RealLive
        .disassemble_with_options(&data, None, &options)?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(script.sections[0].raw, &data[..0x1d4]);
    assert_eq!(script.sections[1].raw, code);
    assert_eq!(
        script.instructions[0].opcode.native_mnemonic.as_deref(),
        Some("entrypoint")
    );
    assert_eq!(
        script.instructions[2].opcode.operation,
        Operation::Text(TextOperation::Show)
    );
    assert!(matches!(&script.instructions[2].args[0].value,Value::Text(s) if s=="hello"));
    assert_eq!(script.instructions[3].opcode.code, 0x010d0000);
    assert!(
        matches!(script.instructions[3].args.last().map(|a|&a.value),Some(Value::Expression(tokens)) if tokens[0].raw==[b'(',b'$',0xff,42,0,0,0,b')'])
    );
    Ok(())
}

#[test]
fn jump_address_low_byte_is_not_an_argument_delimiter() -> Result<()> {
    let mut code = vec![b'#', 0, 1, 0, 0, 0, 0, 0];
    code.extend([b'(', 0, 0, 0]);
    code.resize(40, 0);
    code.extend(b"target");
    let (data, options) = scene(&code, false)?;
    let script = RealLive
        .disassemble_with_options(&data, None, &options)?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(script.instructions[0].span.size, 12);
    assert!(matches!(
        script.instructions[0].args.last().map(|a| &a.value),
        Some(Value::CodeAddress(0x1fc))
    ));
    Ok(())
}

#[test]
fn secondary_window_is_inclusive_and_missing_key_does_not_fall_back() -> Result<()> {
    let code = vec![b'x'; 0x220];
    let (data, mut options) = scene(&code, true)?;
    let decoded = decode(&data, &options)?;
    assert_eq!(&decoded[0x1d4..], code);
    options.keys.remove("reallive_key1");
    assert!(matches!(
        decode(&data, &options),
        Err(Error::UnknownScheme(_))
    ));
    for end in [0, 3, 40, 0x1cf, data.len() - 1] {
        assert!(Header::parse(&data[..end]).is_err());
    }
    Ok(())
}

#[test]
fn display_quotes_escapes_and_raw_bytecode_are_preserved() -> Result<()> {
    let code = b"\"quoted \\\"word\\\"\"";
    let (data, options) = scene(code, false)?;
    let script = RealLive
        .disassemble_with_options(&data, None, &options)?
        .ok_or(Error::InvalidFormat)?;
    assert!(
        matches!(&script.instructions[0].args[0].value, Value::Text(text) if text == "quoted \"word\"")
    );
    assert_eq!(script.sections[1].raw, code);
    let (data, options) = scene(b"\"unterminated", false)?;
    assert!(
        matches!(RealLive.disassemble_with_options(&data, None, &options), Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof)
    );
    Ok(())
}
