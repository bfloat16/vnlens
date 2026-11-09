#![allow(clippy::unwrap_used)]

use super::*;
use crate::ScriptFormat;
use crate::ir::{ControlFlowOperation, Operation};
use crate::will::Ws2;
use nvlens_io::BinaryWriter;
fn schema(records: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for id in 0..=255 {
        if let Some((_, types)) = records.iter().find(|(i, _)| *i == id) {
            out.extend_from_slice(types);
            out.push(255);
        } else {
            out.push(254);
        }
    }
    out
}
fn string(data: &mut Vec<u8>, text: &str) {
    for unit in text.encode_utf16().chain([0]) {
        let mut b = [0; 2];
        BinaryWriter::u16_le(unit, &mut b);
        data.extend(b);
    }
}
#[test]
fn utf16_repeats_and_choice_command_use_engine_schema() {
    let table = schema(&[(1, &[6, 8, 7, 9]), (15, &[0]), (2, &[4])]);
    let mut data = vec![1];
    string(&mut data, "あ🦀");
    data.push(2);
    string(&mut data, "one");
    string(&mut data, "two");
    data.extend([15, 1, 7, 0]);
    string(&mut data, "choice");
    data.extend([1, 255, 255, 2, 42, 0, 0, 0, 255]);
    data.extend([1, 2, 3, 4, 5, 6, 7, 8]);
    let script = parse(&data, &table, TextEncoding::Utf16).unwrap();
    assert_eq!(script.instructions.len(), 3);
    assert_eq!(
        script.instructions[2].opcode.operation,
        Operation::ControlFlow(ControlFlowOperation::Halt)
    );
    assert!(matches!(&script.instructions[0].args[0].value,Value::Text(s) if s=="あ🦀"));
    assert!(
        matches!(&script.instructions[1].args[1].value, Value::Group(f)
            if matches!(f.last().map(|f| &f.value), Some(Value::Expression(tokens))
                if tokens[0].opcode.operation == Operation::ControlFlow(ControlFlowOperation::Jump)
                && matches!(tokens[0].args[0].value, Value::CodeAddress(42))))
    );
    assert_eq!(script.sections[1].raw, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(parse(&data[..10], &table, TextEncoding::Utf16).is_err());
    assert!(Ws2.disassemble(&data, None).is_err());
}
#[test]
fn float_bits_unknown_opcodes_and_truncated_operands_are_retained() {
    let table = schema(&[(1, &[5])]);
    let mut bytes = vec![1, 1, 0, 0xc0, 0x7f, 3];
    bytes.extend([0; 8]);
    let ir = parse(&bytes, &table, TextEncoding::Utf16).unwrap();
    assert!(matches!(
        ir.instructions[0].args[0].value,
        Value::Float32Bits(0x7fc00001)
    ));
    assert_eq!(ir.instructions[1].opcode.operation, Operation::Unknown);
    let mut short = vec![1, 0];
    short.extend([0; 8]);
    assert!(parse(&short, &table, TextEncoding::Utf16).is_err());
}
