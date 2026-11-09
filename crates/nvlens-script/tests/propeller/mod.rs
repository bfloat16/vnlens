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
    let script = parse(&data)?;
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
    assert!(parse(&data[..data.len() - 1]).is_err());
    data.extend([7, 0]);
    assert!(parse(&data).is_err());
    Ok(())
}

#[test]
fn variable_and_random_operands_preserve_native_type_and_one_based_id() -> Result<()> {
    let data = [1, 7, 0, 3, 10, 0];
    let mut r = BinaryReader::new(&data);
    let variable = value(&data, &mut r, 0)?;
    let random = value(&data, &mut r, 1)?;
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
