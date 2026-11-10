#![allow(clippy::unwrap_used)]

use super::*;
use vnlens_io::BinaryWriter;

fn number(bytes: &mut Vec<u8>, value: u64, size: usize) {
    let start = bytes.len();
    bytes.resize(start + size, 0);
    BinaryWriter::compact_u64_le(value, &mut bytes[start..]).unwrap();
}
fn header(magic: &[u8; 4]) -> Vec<u8> {
    let mut bytes = magic.to_vec();
    number(&mut bytes, 0x1ee, 4);
    bytes
}
fn parse(bytes: &[u8]) -> Script {
    super::super::ybn::disassemble(bytes, None).unwrap()
}
fn complete(bytes: &[u8]) {
    let ir = parse(bytes);
    assert_eq!(ir.sections[0].raw, bytes);
    let mut position = 0;
    for instruction in &ir.instructions {
        assert_eq!(instruction.span.offset, position);
        position += instruction.span.size;
    }
    assert_eq!(position, bytes.len() as u64);
    for end in 0..bytes.len() {
        assert!(
            super::super::ybn::disassemble(&bytes[..end], None).is_err(),
            "Accepted truncated table at {end}"
        );
    }
    let mut extra = bytes.to_vec();
    extra.push(0);
    assert!(super::super::ybn::disassemble(&extra, None).is_err());
}

#[test]
fn variable_header_is_ten_bytes_and_initializers_are_typed() {
    let mut bytes = header(b"YSVR");
    number(&mut bytes, 3, 2);
    for (id, ty, dimensions) in [
        (0x1234, 1, &[2u32, 3][..]),
        (0x1235, 2, &[][..]),
        (0x1236, 3, &[][..]),
    ] {
        bytes.extend_from_slice(&[2, 1]);
        number(&mut bytes, 7, 2);
        number(&mut bytes, id, 2);
        bytes.extend_from_slice(&[ty, dimensions.len() as u8]);
        for &dimension in dimensions {
            number(&mut bytes, u64::from(dimension), 4);
        }
        match ty {
            1 => number(&mut bytes, u64::MAX, 8),
            2 => number(&mut bytes, 0x8000_0000_0000_0000, 8),
            _ => {
                let expression = b"M\x03\x00\"x\"";
                number(&mut bytes, expression.len() as u64, 2);
                bytes.extend_from_slice(expression);
            }
        }
    }
    complete(&bytes);
    let ir = parse(&bytes);
    assert_eq!(ir.instructions[1].span.offset, 10);
    assert_eq!(ir.instructions[1].opcode.code, 0x1234);
    assert!(matches!(
        ir.instructions[1].args.last().unwrap().value,
        Value::Integer(-1)
    ));
    assert!(matches!(
        ir.instructions[2].args.last().unwrap().value,
        Value::Float64Bits(0x8000_0000_0000_0000)
    ));
    assert!(
        matches!(&ir.instructions[3].args.last().unwrap().value, Value::Expression(t) if matches!(&t[0].args.first().map(|arg| &arg.value),Some(Value::Text(s)) if s == "x"))
    );
}

#[test]
fn labels_include_hash_buckets_and_cross_script_targets() {
    let mut bytes = header(b"YSLB");
    number(&mut bytes, 1, 4);
    for _ in 0..256 {
        number(&mut bytes, 0, 4);
    }
    bytes.push(5);
    bytes.extend_from_slice(b"hello");
    number(&mut bytes, 0xe561_29cb, 4);
    number(&mut bytes, 42, 4);
    number(&mut bytes, 7, 2);
    bytes.extend_from_slice(&[2, 3]);
    complete(&bytes);
    let ir = parse(&bytes);
    assert_eq!(ir.instructions.len(), 258);
    assert!(
        ir.instructions
            .last()
            .unwrap()
            .args
            .iter()
            .any(|p| p.name == ArgName::Instruction
                && matches!(p.value, Value::InstructionTarget(42)))
    );
    let length = bytes.len();
    bytes[length - 12] ^= 1;
    assert!(super::super::ybn::disassemble(&bytes, None).is_err());
}

#[test]
fn script_list_starts_records_at_twelve_and_preserves_unused_fields() {
    let mut bytes = header(b"YSTL");
    number(&mut bytes, 1, 4);
    number(&mut bytes, 7, 4);
    number(&mut bytes, 8, 4);
    bytes.extend_from_slice(b"main.yst");
    for value in 1..=5 {
        number(&mut bytes, value, 4);
    }
    complete(&bytes);
    let ir = parse(&bytes);
    assert_eq!(ir.instructions[1].span.offset, 12);
    assert_eq!(ir.instructions[1].args.len(), 8);
    assert_eq!(script_paths(&bytes).unwrap(), [(7, "main.yst".into())]);
    for end in 0..bytes.len() {
        assert!(script_paths(&bytes[..end]).is_err());
    }
    bytes[0] = b'X';
    assert!(script_paths(&bytes).is_err());
}

#[test]
fn command_table_includes_messages_and_key_mapping() {
    let mut bytes = header(b"YSCM");
    number(&mut bytes, 1, 4);
    number(&mut bytes, 0, 4);
    bytes.extend_from_slice(b"TEST\x00\x01VALUE\x00\x01\x02");
    for _ in 0..37 {
        bytes.extend_from_slice(b"message\0");
    }
    bytes.extend(0..=255);
    complete(&bytes);
    let ir = parse(&bytes);
    assert_eq!(ir.instructions.len(), 295);
    assert_eq!(
        ir.instructions[1].opcode.native_mnemonic.as_deref(),
        Some("TEST")
    );
    assert_eq!(
        ir.instructions[1].opcode.operation,
        Operation::Data(DataOperation::Record)
    );
    assert_eq!(ir.instructions.last().unwrap().opcode.code, 255);
}

#[test]
fn configuration_metadata_and_errors_are_structured() {
    let mut config = header(b"YSCF");
    config.resize(76, 0);
    number(&mut config, 4, 2);
    config.extend_from_slice(b"Game");
    complete(&config);
    assert!(
        parse(&config).instructions[1]
            .args
            .iter()
            .any(|p| p.name == ArgName::Title && matches!(&p.value,Value::Text(s) if s == "Game"))
    );
    let mut metadata = header(b"YSTD");
    number(&mut metadata, 0x1234, 4);
    number(&mut metadata, 10, 4);
    complete(&metadata);
    let mut errors = header(b"YSER");
    number(&mut errors, 1, 4);
    number(&mut errors, 0, 4);
    number(&mut errors, 7, 4);
    errors.extend_from_slice(b"error\0");
    complete(&errors);
}
