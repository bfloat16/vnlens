use super::*;
use nvlens_io::BinaryWriter;

#[test]
fn labeled_call_signed_values_text_and_unknown_boundaries() -> Result<()> {
    let mut data = vec![0; 21];
    BinaryWriter::u32_le(21, &mut data[2..]);
    BinaryWriter::u32_le(7, &mut data[6..]);
    BinaryWriter::u16_le(1, &mut data[11..]);
    BinaryWriter::u32_le(5, &mut data[13..]);
    data.extend([0, 3, 0, 1, 0]); // Call label 1, whose body starts below.
    data.extend([5, 0, 0, 0xff, 0xff, 2, 0, 0x82, 0xa0]);
    data.extend([0, 4]);
    let script = parse(&data, Layout::V10)?;
    assert_eq!(script.sections[0].raw, data);
    assert_eq!(script.instructions.len(), 4);
    assert_eq!(
        script.instructions[1].opcode.operation,
        Operation::ControlFlow(ControlFlowOperation::Call)
    );
    assert!(matches!(
        script.instructions[1].args[1].value,
        Value::CodeAddress(26)
    ));
    assert!(matches!(
        script.instructions[2].args[0].value,
        Value::Integer(-1)
    ));
    assert!(matches!(&script.instructions[2].args[1].value, Value::Text(t) if t == "あ"));
    assert!(parse(&data[..data.len() - 1], Layout::V10).is_err());
    data.extend([7, 0]);
    assert!(parse(&data, Layout::V10).is_err());
    Ok(())
}

#[test]
fn variable_and_random_operands_preserve_native_type_and_one_based_id() -> Result<()> {
    let data = [1, 7, 0, 3, 10, 0];
    let mut r = BinaryReader::new(&data);
    let variable = value(&data, &mut r, 0, Layout::V10)?;
    let random = value(&data, &mut r, 1, Layout::V10)?;
    assert_eq!(variable.attributes[0].value, 1);
    let Value::Expression(tokens) = variable.value else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(
        tokens[0].opcode.operation,
        Operation::Storage(StorageOperation::Load)
    );
    assert!(matches!(tokens[0].args[1].value, Value::Integer(7)));
    let Value::Expression(tokens) = random.value else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(
        tokens[0].opcode.operation,
        Operation::Basic(BasicOperation::Random)
    );
    assert_eq!(tokens[0].raw, [3, 10, 0]);
    Ok(())
}

#[test]
fn v14_wide_operands_labels_runtime_values_and_conditional_arguments() -> Result<()> {
    let mut data = vec![0; 23];
    BinaryWriter::u32_le(23, &mut data[2..]);
    BinaryWriter::u32_le(9, &mut data[6..]);
    BinaryWriter::u32_le(1, &mut data[11..]);
    BinaryWriter::u32_le(7, &mut data[15..]);
    let word = |data: &mut Vec<u8>, value: u32| {
        let at = data.len();
        data.resize(at + 4, 0);
        BinaryWriter::u32_le(value, &mut data[at..]);
    };
    data.extend([0, 3, 0]); // Call label 1.
    word(&mut data, 1);
    data.extend([5, 0, 0]); // Signed value beyond the v1.0a width and CP932 text.
    word(&mut data, (-70000i32) as u32);
    word(&mut data, 2);
    data.extend([0x82, 0xa0]);
    data.extend([4, 0, 0]); // Event selector 4 has a label in v1.4.
    word(&mut data, 1);
    data.extend([4, 0]);
    word(&mut data, 1);
    data.extend([0, 5, 7]); // Runtime value still consumes its reserved word.
    word(&mut data, 0xabcdef01);
    data.push(1);
    data.extend([1, 0x1a, 2]); // Unimplemented selector consumes no setting byte.
    data.extend([6, 0]); // Music has an additional tagged volume argument.
    word(&mut data, 3);
    data.extend(b"BGM");
    data.extend([1, 0]);
    word(&mut data, 10);
    data.push(0);
    word(&mut data, 25);
    data.extend([0, 4]);

    let mut options = ArchiveOptions::default();
    options.numbers.insert("propeller_msc_version", 14);
    let script = Msc
        .disassemble_with_options(&data, None, &options)?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(script.format_version, 14);
    assert_eq!(script.sections[0].raw, data);
    assert_eq!(script.instructions.len(), 8);
    assert!(matches!(
        script.instructions[1].args[1].value,
        Value::CodeAddress(30)
    ));
    assert!(matches!(
        script.instructions[2].args[0].value,
        Value::Integer(-70000)
    ));
    assert!(matches!(&script.instructions[2].args[1].value, Value::Text(t) if t == "あ"));
    assert!(matches!(
        script.instructions[3].args[3].value,
        Value::CodeAddress(30)
    ));
    let Value::Expression(tokens) = &script.instructions[4].args[0].value else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(tokens[0].raw, [7, 1, 0xef, 0xcd, 0xab]);
    assert_eq!(script.instructions[5].args.len(), 1);
    assert_eq!(script.instructions[6].args.len(), 4);
    assert!(matches!(
        script.instructions[6].args[3].value,
        Value::Integer(25)
    ));
    for instruction in &script.instructions {
        let start = instruction.span.offset as usize;
        let end = start + instruction.span.size as usize;
        for cut in start + 1..end {
            assert!(
                Msc.disassemble_with_options(&data[..cut], None, &options)
                    .is_err(),
                "cut {cut}"
            );
        }
    }
    assert!(Msc.disassemble(&data, None).is_err());
    options.numbers.insert("propeller_msc_version", 15);
    assert!(Msc.disassemble_with_options(&data, None, &options).is_err());
    Ok(())
}
