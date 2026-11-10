use super::*;
use vnlens_io::BinaryWriter;
#[test]
fn compact_variable_operands_references_and_data_are_lossless() -> Result<()> {
    let body = [
        0x12, 0x7f, 0x05, 14, 0, 0x03, 1, 0x7f, 2, 0x15, 9, 4, 0, 0x17, 0, 0, b'h', b'i', 0,
    ];
    let mut bytes = vec![0; 16];
    BinaryWriter::u32_le(16, &mut bytes);
    BinaryWriter::u32_le(body.len() as u32, &mut bytes[4..]);
    bytes.extend(body);
    let script = parse(&bytes)?;
    assert_eq!(script.instructions.len(), 5);
    assert!(matches!(
        script.instructions[0].args[0].value,
        Value::Integer(-1)
    ));
    assert!(matches!(script.instructions[1].args[1].value,Value::Text(ref text) if text=="hi"));
    assert!(matches!(
        script.instructions[2].args[1].value,
        Value::Integer(-1)
    ));
    assert_eq!(
        script.instructions[3].span,
        Span {
            offset: 25,
            size: 4
        }
    );
    assert_eq!(
        script
            .sections
            .iter()
            .flat_map(|s| s.raw.iter().copied())
            .collect::<Vec<_>>(),
        bytes
    );
    let end = bytes.len() - 1;
    assert!(parse(&bytes[..end]).is_err());
    Ok(())
}
