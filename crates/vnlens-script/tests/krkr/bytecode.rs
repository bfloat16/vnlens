use super::*;
use vnlens_io::BinaryWriter;
fn word(b: &mut Vec<u8>, v: u32) {
    let p = b.len();
    b.resize(p + 4, 0);
    BinaryWriter::u32_le(v, &mut b[p..]);
}
fn short(b: &mut Vec<u8>, v: i16) {
    let p = b.len();
    b.resize(p + 2, 0);
    BinaryWriter::u16_le(v as u16, &mut b[p..]);
}
fn fixture(code: &[i16]) -> Vec<u8> {
    let data = text_pool();
    assemble(
        data,
        &[object(
            code,
            &[(3, 0)],
            &[(0, 42)],
            default_header(),
            &[],
            &[],
        )],
        0,
    )
}

fn text_pool() -> Vec<u8> {
    let mut data = vec![0; 20];
    word(&mut data, 1);
    let text = "日本😀";
    word(&mut data, text.encode_utf16().count() as u32);
    for w in text.encode_utf16() {
        short(&mut data, w as i16);
    }
    while !data.len().is_multiple_of(4) {
        data.push(0);
    }
    word(&mut data, 0);
    data
}

fn default_header() -> [i32; 12] {
    [-1, 0, 0, 0, 2, 0, 0, 0, -1, -1, -1, -1]
}

fn object(
    code: &[i16],
    constants: &[(i16, i16)],
    source: &[(u32, u32)],
    header: [i32; 12],
    getters: &[u32],
    properties: &[(u32, i32)],
) -> Vec<u8> {
    let mut object = Vec::new();
    for value in header {
        word(&mut object, value as u32);
    }
    word(&mut object, source.len() as u32);
    for &(code, _) in source {
        word(&mut object, code);
    }
    for &(_, text) in source {
        word(&mut object, text);
    }
    word(&mut object, code.len() as u32);
    for &w in code {
        short(&mut object, w);
    }
    while !object.len().is_multiple_of(4) {
        object.push(0);
    }
    word(&mut object, constants.len() as u32);
    for &(kind, index) in constants {
        short(&mut object, kind);
        short(&mut object, index);
    }
    word(&mut object, getters.len() as u32);
    for &getter in getters {
        word(&mut object, getter);
    }
    word(&mut object, properties.len() as u32);
    for &(name, value) in properties {
        word(&mut object, name);
        word(&mut object, value as u32);
    }
    object
}

fn assemble(data: Vec<u8>, records: &[Vec<u8>], top: i32) -> Vec<u8> {
    let mut objects = Vec::new();
    word(&mut objects, top as u32);
    word(&mut objects, records.len() as u32);
    for record in records {
        objects.extend(b"TJS2");
        word(&mut objects, record.len() as u32);
        objects.extend(record);
    }
    let mut bytes = b"TJS2100\0".to_vec();
    word(&mut bytes, 0);
    for (tag, payload) in [(b"DATA", data), (b"OBJS", objects)] {
        bytes.extend(tag);
        word(&mut bytes, (payload.len() + 8) as u32);
        bytes.extend(payload);
    }
    let len = bytes.len() as u32;
    BinaryWriter::u32_le(len, &mut bytes[8..]);
    bytes
}
#[test]
fn constants_expanded_calls_source_spans_and_unknown_width() -> Result<()> {
    let bytes = fixture(&[1, 1, 0, 100, 2, -2, 0, -2, 1, 0, 1, 119]);
    let script = parse(&bytes)?;
    let code = vm(&script);
    assert_eq!(code.len(), 3);
    assert!(
        matches!(&field(group(&code[0].args[1].value), ArgName::Value)?.value,Value::Text(s) if s=="日本😀")
    );
    assert!(matches!(
        code[1].opcode.operation,
        Operation::ControlFlow(ControlFlowOperation::Call)
    ));
    assert!(parse(&fixture(&[119, 200, 7, 8])).is_err());
    assert_eq!(script.sections[0].raw, bytes);
    assert!(
        code[0]
            .attributes
            .iter()
            .any(|a| a.name == "source_offset" && a.value == 42)
    );
    assert!(parse(&fixture(&[1, 1])).is_err());
    assert!(parse(&fixture(&[17, i16::MAX])).is_err());
    for len in 0..bytes.len() {
        assert!(parse(&bytes[..len]).is_err());
    }
    Ok(())
}

fn vm(script: &Script) -> Vec<&Instruction> {
    script
        .instructions
        .iter()
        .filter(|i| i.opcode.namespace == "krkr/tjs2")
        .collect()
}

fn group(value: &Value) -> &[Arg] {
    if let Value::Group(fields) = value {
        fields
    } else {
        &[]
    }
}

fn field(args: &[Arg], name: ArgName) -> Result<&Arg> {
    args.iter()
        .find(|a| a.name == name)
        .ok_or_else(|| bad(0, &format!("Missing test field {name}")))
}

#[test]
fn every_tjs2100_opcode_has_a_semantic_mapping_and_verified_width() -> Result<()> {
    // Widths from TranslateCodeAddress, with zero arguments for CALL/NEW.
    let widths = [
        1, 3, 3, 2, 3, 2, 2, 3, 3, 3, 3, 2, 2, 2, 1, 2, 2, 2, 2, 4, 4, 3, 2, 4, 4, 3, 3, 5, 5, 4,
        3, 5, 5, 4, 3, 5, 5, 4, 3, 5, 5, 4, 3, 5, 5, 4, 3, 5, 5, 4, 3, 5, 5, 4, 3, 5, 5, 4, 3, 5,
        5, 4, 3, 5, 5, 4, 3, 5, 5, 4, 3, 5, 5, 4, 3, 5, 5, 4, 3, 5, 5, 4, 2, 2, 4, 4, 2, 2, 3, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 4, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 4, 4, 2, 1,
        3, 1, 2, 3, 2, 3, 1, 1,
    ];
    let operations = [
        "no_op",
        "load",
        "store",
        "store",
        "store",
        "store",
        "logical_not",
        "equal",
        "equal",
        "less",
        "greater",
        "store",
        "logical_not",
        "logical_not",
        "logical_not",
        "branch",
        "branch",
        "jump",
        "add",
        "add",
        "add",
        "add",
        "subtract",
        "subtract",
        "subtract",
        "subtract",
        "logical_or",
        "logical_or",
        "logical_or",
        "logical_or",
        "logical_and",
        "logical_and",
        "logical_and",
        "logical_and",
        "bit_or",
        "bit_or",
        "bit_or",
        "bit_or",
        "bit_xor",
        "bit_xor",
        "bit_xor",
        "bit_xor",
        "bit_and",
        "bit_and",
        "bit_and",
        "bit_and",
        "shift_right",
        "shift_right",
        "shift_right",
        "shift_right",
        "shift_left",
        "shift_left",
        "shift_left",
        "shift_left",
        "shift_right",
        "shift_right",
        "shift_right",
        "shift_right",
        "add",
        "add",
        "add",
        "add",
        "subtract",
        "subtract",
        "subtract",
        "subtract",
        "remainder",
        "remainder",
        "remainder",
        "remainder",
        "divide",
        "divide",
        "divide",
        "divide",
        "divide",
        "divide",
        "divide",
        "divide",
        "multiply",
        "multiply",
        "multiply",
        "multiply",
        "bit_not",
        "type_of",
        "type_of",
        "type_of",
        "evaluate",
        "evaluate",
        "instance_of",
        "character_code",
        "character_from_code",
        "convert",
        "negate",
        "invalidate",
        "is_valid",
        "convert",
        "convert",
        "convert",
        "convert",
        "call",
        "call",
        "call",
        "call",
        "load",
        "store",
        "store",
        "store",
        "load",
        "store",
        "store",
        "load",
        "store",
        "load",
        "store",
        "store",
        "load",
        "store",
        "store",
        "store",
        "return",
        "register_exception",
        "unregister_exception",
        "halt",
        "bind_context",
        "load",
        "engine_call",
        "engine_call",
        "engine_call",
    ];
    assert_eq!(widths.len(), 128);
    assert_eq!(operations.len(), 128);
    for (op, (&width, &operation)) in widths.iter().zip(&operations).enumerate() {
        let mut words = vec![0; width];
        words[0] = op as i16;
        words.push(119);
        let script = parse(&fixture(&words))?;
        let code = vm(&script);
        assert_eq!(code.len(), 2, "opcode {op}");
        assert_eq!(code[0].span.size, width as u64 * 2, "opcode {op}");
        assert_eq!(code[0].opcode.operation.name(), operation, "opcode {op}");
        assert!(code[0].opcode.native_mnemonic.is_some(), "opcode {op}");
        for end in 1..width {
            assert!(
                matches!(parse(&fixture(&words[..end])), Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof),
                "opcode {op}, words {end}"
            );
        }
    }
    Ok(())
}

#[test]
fn property_modes_keep_constant_indices_registers_and_write_back() -> Result<()> {
    let script = parse(&fixture(&[
        19, 0, -2, 0, 59, 4, -1, 0, -3, 60, 0, -2, 3, 4, 106, -1, 0, 2, 110, 1, -2, 0, 111, -1, 0,
        1, 118, 1, 119,
    ]))?;
    let code = vm(&script);
    for (i, name) in [
        (0, ArgName::Source),
        (1, ArgName::Left),
        (3, ArgName::Destination),
        (4, ArgName::Source),
        (5, ArgName::Destination),
    ] {
        let property = field(&code[i].args, name)?;
        let key = field(group(&property.value), ArgName::Index)?;
        let reference = group(&key.value);
        assert!(matches!(
            field(reference, ArgName::ConstantIndex)?.value,
            Value::Integer(0)
        ));
        let value = field(reference, ArgName::Value)?;
        assert!(matches!(&value.value, Value::Text(s) if s == "日本😀"));
        assert_eq!(value.span.size, 0);
    }
    let left = field(&code[2].args, ArgName::Left)?;
    let key = field(group(&left.value), ArgName::Index)?;
    assert!(matches!(
        field(group(&key.value), ArgName::Register)?.value,
        Value::Integer(3)
    ));
    assert!(
        left.attributes
            .iter()
            .any(|a| a.name == "write_back" && a.value == 1)
    );
    let destination = field(&code[3].args, ArgName::Destination)?;
    assert!(
        destination
            .attributes
            .iter()
            .any(|a| a.name == "ensure_member" && a.value == 1)
    );
    assert!(
        destination
            .attributes
            .iter()
            .any(|a| a.name == "hidden_member" && a.value == 1)
    );
    assert!(
        field(&code[4].args, ArgName::Source)?
            .attributes
            .iter()
            .any(|a| a.name == "ignore_property" && a.value == 1)
    );
    assert_eq!(code[6].opcode.variant, Some(Qualifier::ReturnValue));
    assert_eq!(
        code[7].opcode.operation,
        Operation::ControlFlow(ControlFlowOperation::Return)
    );
    Ok(())
}

#[test]
fn calls_preserve_forwarded_expanded_unnamed_and_unknown_descriptors() -> Result<()> {
    for op in 99..=102 {
        for count in [-1, -2, 2] {
            let mut words = vec![op, 0, -2];
            if matches!(op, 100 | 101) {
                words.push(0);
            }
            words.push(count);
            if count == -2 {
                words.extend([4, 0, -3, 1, 4, 2, i16::MIN, 77, 123]);
            }
            if count == 2 {
                words.extend([-3, 0]);
            }
            let size = words.len();
            words.push(119);
            let script = parse(&fixture(&words))?;
            let code = vm(&script);
            assert_eq!(code.len(), 2);
            assert_eq!(code[0].span.size, size as u64 * 2);
            assert!(
                matches!(field(&code[0].args, ArgName::ArgumentCount)?.value, Value::Integer(v) if v == i64::from(count))
            );
            let arguments = field(&code[0].args, ArgName::Arguments)?;
            if count == -1 {
                assert!(
                    matches!(&arguments.value, Value::Expression(tokens) if tokens.len() == 1 && tokens[0].opcode.operation == Operation::Storage(StorageOperation::GetArguments))
                );
                assert_eq!(arguments.span.size, 0);
            } else if count == -2 {
                let rows = group(&arguments.value);
                assert_eq!(rows.len(), 4);
                assert!(matches!(
                    field(group(&rows[2].value), ArgName::Reserved)?.value,
                    Value::Integer(-32768)
                ));
                assert!(matches!(
                    field(group(&rows[3].value), ArgName::Unknown(1))?.value,
                    Value::Integer(123)
                ));
            } else {
                assert_eq!(group(&arguments.value).len(), 2);
            }
        }
    }
    for code in [
        &[99, 1, 2, -3][..],
        &[99, 1, 2, -2, -1],
        &[17, 1, 119],
        &[120, 1, 1, 119],
    ] {
        assert!(parse(&fixture(code)).is_err());
    }
    let script = parse(&fixture(&[0, 15, -1, 16, -3, 120, -5, -3, 119]))?;
    let code = vm(&script);
    for i in 1..=3 {
        assert!(
            matches!(field(&code[i].args, ArgName::Target)?.value, Value::CodeAddress(at) if at == code[0].span.offset)
        );
        assert_eq!(field(&code[i].args, ArgName::Delta)?.span.size, 2);
        assert_eq!(field(&code[i].args, ArgName::Target)?.span.size, 0);
    }
    assert_eq!(code[1].opcode.variant, Some(Qualifier::Nonzero));
    assert_eq!(code[2].opcode.variant, Some(Qualifier::Zero));
    Ok(())
}

#[test]
fn flag_state_in_place_invalidation_and_discarded_results_are_explicit() -> Result<()> {
    let script = parse(&fixture(&[
        5, -3, 6, -4, 7, 1, 2, 11, 1, 12, 2, 14, 93, 3, 19, 0, -2, 0, 119,
    ]))?;
    let code = vm(&script);
    for (i, name, operation) in [
        (0, ArgName::Destination, StorageOperation::Reference),
        (1, ArgName::Destination, StorageOperation::Reference),
        (2, ArgName::Destination, StorageOperation::Reference),
        (3, ArgName::Source, StorageOperation::Load),
        (4, ArgName::Source, StorageOperation::Load),
        (5, ArgName::Source, StorageOperation::Load),
    ] {
        let flag = field(&code[i].args, name)?;
        assert_eq!(flag.span.size, 0);
        assert!(
            matches!(&flag.value, Value::Expression(tokens) if tokens.len() == 1 && tokens[0].opcode.operation == Operation::Storage(operation) && tokens[0].opcode.variant == Some(Qualifier::Flag))
        );
    }
    assert!(matches!(
        field(
            group(&field(&code[6].args, ArgName::Destination)?.value),
            ArgName::Register
        )?
        .value,
        Value::Integer(3)
    ));
    assert!(
        field(&code[7].args, ArgName::Destination)?
            .attributes
            .iter()
            .any(|a| a.name == "discard_result" && a.value == 1)
    );
    assert!(
        field(&code[7].args, ArgName::Source)?
            .attributes
            .iter()
            .any(|a| a.name == "write_back" && a.value == 1)
    );
    // ContinuousClear uses r < r + count, so a negative count clears no slots.
    let script = parse(&fixture(&[4, 1, -1, 119]))?;
    assert!(matches!(
        field(&vm(&script)[0].args, ArgName::Count)?.value,
        Value::Integer(-1)
    ));
    Ok(())
}

#[test]
fn signatures_versions_chunk_lengths_and_object_ranges_are_checked() -> Result<()> {
    let bytes = fixture(&[119]);
    for (at, replacement) in [(0, b'X'), (6, b'1'), (12, b'X')] {
        let mut damaged = bytes.clone();
        damaged[at] = replacement;
        assert!(parse(&damaged).is_err());
    }
    let mut damaged = bytes.clone();
    BinaryWriter::u32_le(7, &mut damaged[16..]);
    assert!(parse(&damaged).is_err());
    let mut damaged = bytes.clone();
    BinaryWriter::u32_le(u32::MAX, &mut damaged[16..]);
    assert!(
        matches!(parse(&damaged), Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof)
    );
    for field in [0, 9, 10, 11] {
        let mut header = default_header();
        header[field] = 1;
        assert!(
            parse(&assemble(
                text_pool(),
                &[object(&[119], &[], &[], header, &[], &[])],
                0
            ))
            .is_err()
        );
    }
    assert!(
        parse(&assemble(
            text_pool(),
            &[object(&[119], &[], &[], default_header(), &[], &[(1, 0)])],
            0
        ))
        .is_err()
    );
    Ok(())
}

#[test]
fn typed_pools_preserve_signed_values_nan_payloads_octets_and_object_kinds() -> Result<()> {
    let mut data = Vec::new();
    word(&mut data, 1);
    data.extend([128, 0xaa, 0xbb, 0xcc]);
    word(&mut data, 1);
    short(&mut data, i16::MIN);
    short(&mut data, 0x1234);
    word(&mut data, 1);
    word(&mut data, i32::MIN as u32);
    word(&mut data, 1);
    let mut value = [0; 8];
    BinaryWriter::u64_le(i64::MIN as u64, &mut value);
    data.extend(value);
    word(&mut data, 1);
    BinaryWriter::u64_le(0xfff8_0000_1234_5678, &mut value);
    data.extend(value);
    word(&mut data, 1);
    word(&mut data, 4);
    for unit in "名\0😀".encode_utf16() {
        short(&mut data, unit as i16);
    }
    word(&mut data, 1);
    word(&mut data, 3);
    data.extend([0, 255, 1, 0xee]);
    let constants = [
        (0, -1),
        (1, -1),
        (2, 0),
        (3, 0),
        (4, 0),
        (5, 0),
        (6, 0),
        (7, 0),
        (8, 0),
        (9, 0),
        (10, 0),
        (-1, 42),
    ];
    let mut code = Vec::new();
    for i in 0..constants.len() {
        code.extend([1, 1, i as i16]);
    }
    code.push(119);
    let bytes = assemble(
        data.clone(),
        &[object(&code, &constants, &[], default_header(), &[], &[])],
        0,
    );
    let script = parse(&bytes)?;
    let code = vm(&script);
    let values = code[..constants.len()]
        .iter()
        .map(|i| field(group(&i.args[1].value), ArgName::Value).map(|a| &a.value))
        .collect::<Result<Vec<_>>>()?;
    assert!(matches!(values[0], Value::Nil));
    assert!(matches!(
        field(group(values[1]), ArgName::Value)?.value,
        Value::Nil
    ));
    for i in [2, 10] {
        assert!(matches!(
            field(group(values[i]), ArgName::FunctionIndex)?.value,
            Value::Integer(0)
        ));
        assert!(
            matches!(field(group(values[i]), ArgName::Target)?.value, Value::CodeAddress(at) if at == code[0].span.offset)
        );
    }
    assert!(matches!(values[3], Value::Text(s) if s == "名\0😀"));
    assert!(matches!(values[4], Value::Bytes(b) if b == &[0,255,1]));
    assert!(matches!(
        values[5],
        Value::Float64Bits(0xfff8_0000_1234_5678)
    ));
    for (i, expected) in [
        (6, -128),
        (7, -32768),
        (8, i64::from(i32::MIN)),
        (9, i64::MIN),
    ] {
        assert!(matches!(values[i], Value::Integer(v) if *v == expected));
    }
    assert!(matches!(
        field(group(values[11]), ArgName::Unknown(1))?.value,
        Value::Integer(42)
    ));
    assert_eq!(script.sections[0].raw, bytes);
    script.to_json()?;
    for constants in [&[(3, -1)][..], &[(3, 1)], &[(2, -1)], &[(2, 1)], &[(10, 1)]] {
        assert!(
            parse(&assemble(
                data.clone(),
                &[object(&[119], constants, &[], default_header(), &[], &[])],
                0
            ))
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn metadata_keeps_empty_objects_forward_links_properties_and_duplicate_source_rows() -> Result<()> {
    let mut root = default_header();
    root[11] = 2;
    let mut property = default_header();
    property[0] = 0;
    property[2] = 3;
    property[10] = 2;
    let mut getter = default_header();
    getter[0] = 1;
    getter[2] = 7;
    getter[7] = 3;
    getter[8] = 5;
    let records = [
        object(
            &[1, 1, 0, 119],
            &[(2, 1)],
            &[(0, 41), (0, 42), (3, 77)],
            root,
            &[],
            &[],
        ),
        object(&[], &[], &[], property, &[], &[(0, 1)]),
        object(&[118, -3, 119], &[], &[], getter, &[0, 2], &[]),
    ];
    let script = parse(&assemble(text_pool(), &records, 0))?;
    let code = vm(&script);
    assert_eq!(code.len(), 4);
    assert_eq!(code[0].source_line, None);
    assert!(
        code[0]
            .attributes
            .iter()
            .any(|a| a.name == "source_offset" && a.value == 42)
    );
    assert!(
        code[1]
            .attributes
            .iter()
            .any(|a| a.name == "source_offset" && a.value == 77)
    );
    let metadata = script
        .instructions
        .iter()
        .filter(|i| i.opcode.native_mnemonic.as_deref() == Some("object"))
        .collect::<Vec<_>>();
    assert_eq!(metadata.len(), 3);
    assert_eq!(
        group(&field(&metadata[0].args, ArgName::SourceMap)?.value).len(),
        3
    );
    assert!(matches!(
        field(&metadata[1].args, ArgName::GetterIndex)?.value,
        Value::Integer(2)
    ));
    assert_eq!(
        group(&field(&metadata[1].args, ArgName::Properties)?.value).len(),
        1
    );
    assert_eq!(
        group(&field(&metadata[2].args, ArgName::Targets)?.value).len(),
        2
    );
    let empty = field(group(&code[0].args[1].value), ArgName::Value)?;
    assert!(matches!(
        field(group(&empty.value), ArgName::FunctionIndex)?.value,
        Value::Integer(1)
    ));
    assert!(
        !group(&empty.value)
            .iter()
            .any(|a| a.name == ArgName::Target)
    );
    for target in [1, 3] {
        let bad_getter = object(&[118, -3, 119], &[], &[], getter, &[target], &[]);
        assert!(
            parse(&assemble(
                text_pool(),
                &[records[0].clone(), records[1].clone(), bad_getter],
                0
            ))
            .is_err()
        );
    }
    let mut anonymous = default_header();
    anonymous[1] = -1;
    assert!(
        parse(&assemble(
            vec![0; 28],
            &[object(&[119], &[], &[], anonymous, &[], &[])],
            0
        ))
        .is_ok()
    );
    assert!(parse(&assemble(text_pool(), &records, 3)).is_err());
    Ok(())
}

#[test]
fn name_hints_fold_known_register_strings_without_crossing_branches() -> Result<()> {
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let direct = fixture(&[1, 1, 0, 2, 2, 1, 58, 1, 2, 119]);
    let names = crate::krkr::name_candidates(&direct, "test.tjs", &cancel)?;
    assert!(names.contains(&"日本😀日本😀".into()));
    let branched = fixture(&[1, 1, 0, 2, 2, 1, 17, 2, 58, 1, 2, 119]);
    assert!(
        !crate::krkr::name_candidates(&branched, "test.tjs", &cancel)?
            .contains(&"日本😀日本😀".into())
    );
    Ok(())
}
