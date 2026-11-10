use super::*;
use vnlens_io::BinaryWriter;
#[test]
fn compiled_condition_immediate_halt_and_font_bytes_are_preserved() -> Result<()> {
    let mut bytes = b"BurikoCompiledScriptVer1.00\0".to_vec();
    bytes.resize(32, 0);
    BinaryWriter::u32_le(4, &mut bytes[28..]);
    for word in [0, 0xfffffff9, 1, 40, 0x17, 1, 3, 48, 0xf4, 0, 0x1b, 0] {
        let mut value = [0; 4];
        BinaryWriter::u32_le(word, &mut value);
        bytes.extend(value);
    }
    bytes.extend([0x81, 0]);
    let script = parse(&bytes)?;
    assert_eq!(script.instructions.len(), 6);
    assert_eq!(
        script.instructions[2].span,
        Span {
            offset: 48,
            size: 8
        }
    );
    assert!(
        matches!(script.instructions[3].args[0].value,Value::Bytes(ref value) if value==&[0x81])
    );
    assert_eq!(
        script.instructions[4].opcode.operation,
        Operation::ControlFlow(ControlFlowOperation::Halt)
    );
    assert_eq!(
        script
            .sections
            .iter()
            .flat_map(|s| s.raw.iter().copied())
            .collect::<Vec<_>>(),
        bytes
    );
    Ok(())
}
