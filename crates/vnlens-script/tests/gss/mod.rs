use super::*;
use vnlens_io::BinaryWriter;

fn instruction(code: u16, operands: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 6];
    BinaryWriter::u16_le(code, &mut bytes);
    bytes[2] = (6 + operands.len()) as u8;
    bytes[3] = 0xa5;
    BinaryWriter::u16_le(123, &mut bytes[4..]);
    bytes.extend_from_slice(operands);
    bytes
}
#[test]
fn typed_arguments_text_unknown_operands_and_source_remain_lossless() -> Result<()> {
    let mut data = b"SCR 3.00".to_vec();
    data.extend_from_slice(&[0; 8]);
    data.extend(instruction(0x5a, b"\x03\x82\xa0\0"));
    data.extend(instruction(0x1c, b"\x03LABEL\0"));
    data.extend(instruction(
        0x1ab,
        b"\x01\xff\xff\xff\xff\x02\x01\x80\x04\x01\0\x05\x03\0\x04\0\x06\x02\xc0\xfe\x11\x22",
    ));
    data.extend_from_slice(b"\0trailer");
    let script = parse(&data, &AtomicBool::new(false))?;
    assert_eq!(script.sections[0].raw, data);
    assert_eq!(script.instructions.len(), 4);
    assert!(matches!(&script.instructions[1].args[0].value, Value::Text(text) if text == "あ"));
    assert_eq!(
        script.instructions[1].opcode.operation,
        Operation::Text(TextOperation::Show)
    );
    assert_eq!(
        script.instructions[2].opcode.operation,
        Operation::ControlFlow(Flow::Call)
    );
    let unknown = &script.instructions[3];
    assert_eq!(unknown.opcode.operation, Operation::Unknown);
    assert_eq!(unknown.opcode.code, 0x1ab);
    assert!(matches!(unknown.args[0].value, Value::Integer(-1)));
    assert!(
        matches!(&unknown.args.last().ok_or(Error::InvalidFormat)?.value, Value::Bytes(bytes) if bytes == &[0xfe, 0x11, 0x22])
    );
    assert_eq!(script.instructions[1].source_line, Some(123));
    assert!(matches!(
        parse(&data, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    Ok(())
}
#[test]
fn invalid_headers_instruction_ranges_and_argument_truncation_fail_without_fallback() -> Result<()>
{
    for length in 0..16 {
        assert!(
            parse(
                &b"SCR 3.00\0\0\0\0\0\0\0\0"[..length],
                &AtomicBool::new(false)
            )
            .is_err()
        );
    }
    let mut data = b"SCR 3.00\0\0\0\0\0\0\0\0".to_vec();
    for operand in [&b"\x01\0"[..], &b"\x03missing_nul"[..], &b"\x05\0\0"[..]] {
        let mut invalid = data.clone();
        invalid.extend(instruction(0x25, operand));
        assert!(
            matches!(parse(&invalid, &AtomicBool::new(false)), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof)
        );
    }
    data.extend_from_slice(&[0x25, 0, 5, 0, 0, 0]);
    assert!(matches!(
        parse(&data, &AtomicBool::new(false)),
        Err(Error::Corrupt { .. })
    ));
    data[4] = b'2';
    assert!(matches!(
        parse(&data, &AtomicBool::new(false)),
        Err(Error::Unsupported(_))
    ));
    data[0] = 0;
    assert!(matches!(
        parse(&data, &AtomicBool::new(false)),
        Err(Error::InvalidFormat)
    ));
    Ok(())
}
