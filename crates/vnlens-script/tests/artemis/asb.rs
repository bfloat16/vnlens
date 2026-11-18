use super::*;
use vnlens_io::BinaryWriter;

fn word(bytes: &mut Vec<u8>, value: u32) {
    let at = bytes.len();
    bytes.resize(at + 4, 0);
    BinaryWriter::u32_le(value, &mut bytes[at..]);
}
fn text(bytes: &mut Vec<u8>, value: &str) {
    word(bytes, value.len() as u32);
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(0);
}
fn fixture() -> Vec<u8> {
    let mut bytes = b"ASB\x17\0".to_vec();
    word(&mut bytes, 3);
    word(&mut bytes, 1);
    text(&mut bytes, "start");
    word(&mut bytes, 0);
    text(&mut bytes, "calllua");
    word(&mut bytes, 42);
    word(&mut bytes, 2);
    text(&mut bytes, "function");
    text(&mut bytes, "日本語('text')");
    text(&mut bytes, "function");
    text(&mut bytes, "duplicate argument is preserved");
    word(&mut bytes, 9);
    text(&mut bytes, "unknown record");
    bytes
}

#[test]
fn command_names_arguments_lines_labels_and_unknown_fields_are_lossless() -> Result<()> {
    let mut bytes = fixture();
    bytes.extend_from_slice(b"tail");
    let ir = crate::disassemble_as("asb/artemis", &bytes, None)?.ok_or(Error::InvalidFormat)?;
    assert_eq!(ir.format_version, 0);
    assert_eq!(ir.sections[0].raw, bytes);
    assert_eq!(ir.instructions.len(), 3);
    let label = &ir.instructions[0];
    assert!(label.opcode.native_mnemonic.is_none());
    assert_eq!(label.attributes[0].value, 0);
    assert!(matches!(&label.args[0].value, Value::Text(s) if s == "start"));
    let command = &ir.instructions[1];
    assert_eq!(command.source_line, Some(42));
    assert_eq!(command.attributes[0].value, 0);
    assert_eq!(command.opcode.native_mnemonic.as_deref(), Some("calllua"));
    assert_eq!(command.args.len(), 2);
    assert_eq!(command.args[0].native_name.as_deref(), Some("function"));
    assert_eq!(command.args[1].native_name.as_deref(), Some("function"));
    assert!(matches!(&command.args[0].value, Value::Text(s) if s == "日本語('text')"));
    assert_eq!(ir.instructions[2].opcode.code, 9);
    assert_eq!(ir.instructions[2].opcode.operation, Operation::Unknown);
    assert!(!ir.to_json()?.is_empty());
    Ok(())
}

#[test]
fn asb_keeps_eof_errors_and_rejects_bad_headers_strings_and_cancellation() {
    let bytes = fixture();
    let cancel = AtomicBool::new(false);
    for end in 0..bytes.len() {
        assert!(
            matches!(read(&bytes[..end], &cancel), Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof)
        );
    }
    assert!(matches!(
        read(&bytes, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    let mut bad = bytes.clone();
    bad[0] = b'x';
    assert!(matches!(read(&bad, &cancel), Err(Error::InvalidFormat)));
    bad = bytes.clone();
    bad[4] = 1;
    assert!(matches!(read(&bad, &cancel), Err(Error::Unsupported(_))));
    bad = bytes.clone();
    bad[17] = 0xff;
    assert!(matches!(read(&bad, &cancel), Err(Error::Corrupt { .. })));
    bad = bytes;
    bad[22] = b'x';
    assert!(matches!(read(&bad, &cancel), Err(Error::Corrupt { .. })));
}
