use super::*;
use nvlens_io::BinaryWriter;
fn word(data: &mut Vec<u8>, value: u32) {
    let at = data.len();
    data.resize(at + 4, 0);
    BinaryWriter::u32_le(value, &mut data[at..]);
}
fn scene(code: &[u8], labels: &[u32], text: &str) -> Vec<u8> {
    let mut data = vec![0; 132];
    BinaryWriter::u32_le(132, &mut data);
    BinaryWriter::u32_le(132, &mut data[4..]);
    BinaryWriter::u32_le(code.len() as u32, &mut data[8..]);
    data.extend(code);
    let index = data.len() as u32;
    word(&mut data, 0);
    word(&mut data, text.encode_utf16().count() as u32);
    let string = data.len() as u32;
    for unit in text.encode_utf16() {
        let at = data.len();
        data.resize(at + 2, 0);
        BinaryWriter::u16_le(unit, &mut data[at..]);
    }
    let label = data.len() as u32;
    for &value in labels {
        word(&mut data, value);
    }
    for (at, value) in [
        (12, index),
        (16, 1),
        (20, string),
        (24, 1),
        (28, label),
        (32, labels.len() as u32),
    ] {
        BinaryWriter::u32_le(value, &mut data[at..]);
    }
    data
}
#[test]
fn native_call_text_marker_nested_types_and_typed_targets() -> Result<()> {
    let mut code = vec![8, 2];
    word(&mut code, 10);
    word(&mut code, 18);
    code.push(2);
    word(&mut code, 10);
    word(&mut code, 7);
    code.push(0x30);
    for value in [0, 1, u32::MAX, 1, 10, 0, 0, 42] {
        word(&mut code, value);
    }
    let text_at = code.len();
    code.push(2);
    word(&mut code, 20);
    word(&mut code, 0);
    code.push(0x31);
    word(&mut code, 42);
    code.push(0x10);
    word(&mut code, 0);
    let source = scene(&code, &[text_at as u32], "你好😀");
    let script = parse(&source)?;
    assert_eq!(script.instructions.len(), 7);
    let call = &script.instructions[3];
    assert_eq!(
        call.opcode.operation,
        Operation::Runtime(RuntimeOperation::EngineCall)
    );
    assert!(
        call.args
            .iter()
            .any(|o| o.name == ArgName::TextId && matches!(o.value, Value::Unsigned(42)))
    );
    assert!(
        script.instructions[4]
            .args
            .iter()
            .any(|o| matches!(&o.value,Value::Text(s) if s=="你好😀"))
    );
    assert!(
        script.instructions[6]
            .args
            .iter()
            .any(|o| matches!(o.value,Value::CodeAddress(a) if a==132+text_at as u64))
    );
    assert_eq!(script.sections[0].raw, source);
    let mut bad = source.clone();
    let labels = BinaryReader::u32_le(&bad[28..]) as usize;
    BinaryWriter::u32_le(text_at as u32 + 1, &mut bad[labels..]);
    assert!(parse(&bad).is_err());
    assert!(parse(&source[..source.len() - 1]).is_err());
    Ok(())
}
#[test]
fn stack_ops_and_arithmetic_keep_shared_names() -> Result<()> {
    let mut code = Vec::new();
    for value in [u32::MAX, 2] {
        code.push(2);
        word(&mut code, 10);
        word(&mut code, value);
    }
    code.push(0x22);
    word(&mut code, 10);
    word(&mut code, 10);
    code.push(1);
    code.push(4);
    word(&mut code, 10);
    code.push(3);
    word(&mut code, 10);
    for operator in [0x35, 0x36] {
        code.push(0x22);
        word(&mut code, 10);
        word(&mut code, 10);
        code.push(operator);
    }
    code.push(0xfe);
    let script = parse(&scene(&code, &[], ""))?;
    assert_eq!(
        script.instructions[2].opcode.operation,
        Operation::Basic(BasicOperation::Add)
    );
    assert_eq!(
        script.instructions[3].opcode.operation,
        Operation::Storage(StorageOperation::Duplicate)
    );
    assert_eq!(
        script.instructions[4].opcode.operation,
        Operation::Storage(StorageOperation::Pop)
    );
    assert_eq!(
        script.instructions[5]
            .opcode
            .variant
            .map(crate::ir::Qualifier::name),
        Some("arithmetic")
    );
    assert_eq!(
        script.instructions[6]
            .opcode
            .variant
            .map(crate::ir::Qualifier::name),
        Some("logical")
    );
    assert_eq!(script.instructions[7].opcode.operation, Operation::Unknown);
    assert_eq!(script.instructions[7].span.size, 1);
    Ok(())
}
