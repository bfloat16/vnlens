use super::*;
use nvlens_io::BinaryWriter;
fn word(bytes: &mut Vec<u8>, value: u32) {
    let mut out = [0; 4];
    BinaryWriter::u32_le(value, &mut out);
    bytes.extend(out);
}
#[test]
fn commands_references_and_utf16_text_are_lossless() -> Result<()> {
    let mut command = b"M#N".to_vec();
    word(&mut command, 39);
    command.push(b'A');
    word(&mut command, 8);
    word(&mut command, 9999);
    let mut text = vec![b'T'];
    word(&mut text, 42);
    let units: Vec<_> = "\u{3042}\u{1f31f}".encode_utf16().collect();
    word(&mut text, units.len() as u32);
    for unit in &units {
        let mut out = [0; 2];
        BinaryWriter::u16_le(unit ^ units.len() as u16, &mut out);
        text.extend(out);
    }
    word(&mut text, 9999);
    let mut bytes = Vec::new();
    for record in [&command, &text] {
        word(&mut bytes, record.len() as u32);
        bytes.extend(record);
    }
    let script = Csystem
        .disassemble(&bytes, None)?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(script.instructions.len(), 2);
    assert_eq!(script.sections[0].raw, bytes);
    assert_eq!(script.instructions[0].opcode.code, 39);
    assert!(
        matches!(&script.instructions[1].args[0].value,Value::Text(t) if t=="\u{3042}\u{1f31f}")
    );
    assert_eq!(script.instructions[1].args[0].attributes[0].value, 42);
    for end in 1..bytes.len() {
        if end == command.len() + 4 {
            continue;
        }
        assert!(
            Csystem.disassemble(&bytes[..end], None).is_err(),
            "length {end}"
        );
    }
    Ok(())
}
