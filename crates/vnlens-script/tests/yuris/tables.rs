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
fn variable_storage_depends_on_the_version_branch() {
    for (version, storage) in [
        (0x12c, false),
        (0x1c6, false),
        (0x1d0, false),
        (0x1da, false),
        (0x1dc, false),
        (0x1df, false),
        (0x1e0, false),
        (0x1e1, true),
        (0x1e6, true),
        (0x1ee, true),
        (0x226, false),
        (0x227, false),
        (0x228, false),
        (0x229, false),
        (0x22a, false),
        (0x22b, true),
    ] {
        let mut bytes = header(b"YSVR");
        BinaryWriter::u32_le(version, &mut bytes[4..]);
        number(&mut bytes, 1, 2);
        bytes.push(2);
        if storage {
            bytes.push(3);
        }
        number(&mut bytes, 7, 2);
        number(&mut bytes, 0x1234, 2);
        bytes.extend_from_slice(&[1, 1]);
        number(&mut bytes, 5, 4);
        number(&mut bytes, u64::MAX, 8);
        complete(&bytes);
        let ir = parse(&bytes);
        let record = &ir.instructions[1];
        assert_eq!(record.span.offset, 10);
        assert_eq!(record.opcode.code, 0x1234);
        assert_eq!(
            record
                .args
                .iter()
                .any(|field| field.name == ArgName::Storage),
            storage
        );
        assert!(matches!(
            record.args.last().unwrap().value,
            Value::Integer(-1)
        ));
    }
    let mut unsupported = header(b"YSVR");
    BinaryWriter::u32_le(0x1e2, &mut unsupported[4..]);
    assert!(super::super::ybn::disassemble(&unsupported, None).is_err());
}

#[test]
fn label_hash_variants_must_agree_across_the_complete_table() {
    use vnlens_crypto::{checksum::crc32, hash::murmur2};
    let make = |hashes: [u32; 2]| {
        let mut bytes = header(b"YSLB");
        number(&mut bytes, 2, 4);
        bytes.resize(12 + 1024, 0);
        for (name, hash) in [b"hello".as_slice(), b"abc"].into_iter().zip(hashes) {
            bytes.push(name.len() as u8);
            bytes.extend_from_slice(name);
            number(&mut bytes, u64::from(hash), 4);
            number(&mut bytes, 42, 4);
            number(&mut bytes, 7, 2);
            bytes.extend_from_slice(&[2, 3]);
        }
        bytes
    };
    let crc = [crc32::ieee(0, b"hello"), crc32::ieee(0, b"abc")];
    let murmur = [murmur2::hash(b"hello", 0), murmur2::hash(b"abc", 0)];
    for hashes in [crc, murmur] {
        let bytes = make(hashes);
        complete(&bytes);
        let ir = parse(&bytes);
        assert_eq!(ir.instructions.len(), 259);
        assert!(
            ir.instructions
                .last()
                .unwrap()
                .args
                .iter()
                .any(|p| p.name == ArgName::Instruction
                    && matches!(p.value, Value::InstructionTarget(42)))
        );
        let labels = labels(&bytes).unwrap();
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0].name, "hello");
        assert_eq!(labels[1].instruction, 42);
        assert_eq!(labels[1].script, 7);
    }
    for hashes in [[crc[0], murmur[1]], [murmur[0], crc[1]], [0, 0]] {
        assert!(super::super::ybn::disassemble(&make(hashes), None).is_err());
    }
}

#[test]
fn script_list_layouts_preserve_version_specific_metadata() {
    for (version, words, second_record, flags) in [
        (0x12c, 4, 44, false),
        (0x1c6, 4, 44, false),
        (0x1d0, 4, 44, false),
        (0x1da, 4, 44, false),
        (0x1dc, 4, 44, false),
        (0x1df, 5, 48, true),
        (0x1ee, 5, 48, true),
        (0x226, 4, 44, false),
        (0x227, 4, 44, false),
        (0x228, 5, 48, true),
    ] {
        let mut bytes = header(b"YSTL");
        BinaryWriter::u32_le(version, &mut bytes[4..]);
        number(&mut bytes, 2, 4);
        for (id, path) in [(7, "main.yst"), (42, "sub.yst")] {
            number(&mut bytes, id, 4);
            number(&mut bytes, path.len() as u64, 4);
            bytes.extend_from_slice(path.as_bytes());
            for word in 1..=words {
                number(&mut bytes, word, 4);
            }
        }
        complete(&bytes);
        let ir = parse(&bytes);
        assert_eq!(ir.instructions[1].span.offset, 12);
        assert_eq!(ir.instructions[2].span.offset, second_record);
        for record in &ir.instructions[1..] {
            assert_eq!(record.args.len(), 3 + words as usize);
            assert_eq!(
                record
                    .args
                    .iter()
                    .any(|field| field.name == ArgName::RuntimeFlags),
                flags
            );
            assert!(
                matches!(record.args.last().unwrap().value, Value::Unsigned(value) if value == words)
            );
        }
        assert_eq!(
            script_paths(&bytes).unwrap(),
            [(7, "main.yst".into()), (42, "sub.yst".into())]
        );
        if version == 0x1ee {
            for end in 0..bytes.len() {
                assert!(script_paths(&bytes[..end]).is_err());
            }
            bytes[0] = b'X';
            assert!(script_paths(&bytes).is_err());
        }
    }
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
    let (definitions, end) = super::commands(&bytes, None).unwrap();
    assert_eq!(definitions[0].name, "TEST");
    assert_eq!(definitions[0].arguments[0].name, "VALUE");
    assert_eq!(end + 37 * 8 + 256, bytes.len());
    for version in [0x12c, 0x1c6, 0x1d0, 0x1da, 0x1dc, 0x1e1, 0x1ee] {
        BinaryWriter::u32_le(version, &mut bytes[4..]);
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
}

#[test]
fn configuration_layouts_and_metadata_tables_are_structured() {
    for (version, prefix_size, options, title_offset, reserved) in [
        (0x12c, 64, 6, 0x42, false),
        (0x1c6, 64, 6, 0x42, false),
        (0x1d0, 64, 6, 0x42, false),
        (0x1da, 64, 6, 0x42, false),
        (0x1dc, 64, 6, 0x42, false),
        (0x1df, 76, 8, 0x4e, true),
        (0x1ee, 76, 8, 0x4e, true),
        (0x226, 64, 6, 0x42, false),
        (0x227, 64, 6, 0x42, false),
        (0x228, 64, 6, 0x42, false),
        (0x229, 76, 8, 0x4e, true),
    ] {
        let mut config = header(b"YSCF");
        BinaryWriter::u32_le(version, &mut config[4..]);
        config.resize(prefix_size, 0);
        number(&mut config, 4, 2);
        config.extend_from_slice(b"Game");
        complete(&config);
        let ir = parse(&config);
        let fields = &ir.instructions[1].args;
        assert_eq!(
            fields
                .iter()
                .filter(|field| matches!(field.name, ArgName::Option(_)))
                .count(),
            options
        );
        assert_eq!(
            fields
                .iter()
                .any(|field| field.name == ArgName::ReservedAt(2)),
            reserved
        );
        let title = fields
            .iter()
            .find(|field| field.name == ArgName::Title)
            .unwrap();
        assert_eq!(title.span.offset, title_offset);
        assert!(matches!(&title.value, Value::Text(text) if text == "Game"));
    }
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
