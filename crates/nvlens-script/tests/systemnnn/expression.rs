use super::*;
use crate::ir::{BasicOperation, ControlFlowOperation};
use nvlens_io::BinaryWriter;

fn words(values: &[u32]) -> Vec<u8> {
    let mut bytes = vec![0; values.len() * 4];
    for (&value, target) in values.iter().zip(bytes.as_chunks_mut::<4>().0) {
        BinaryWriter::u32_le(value, target);
    }
    bytes
}
#[test]
fn postfix_references_compound_stores_and_logical_xor_keep_native_tokens() -> Result<()> {
    for (code, operation, qualifier) in [
        (0xa000002b, Operation::Basic(BasicOperation::Add), None),
        (
            0xa000003d,
            Operation::Storage(StorageOperation::Store),
            Some(Qualifier::Assign),
        ),
        (
            0xa200002b,
            Operation::Storage(StorageOperation::Store),
            Some(Qualifier::AddAssign),
        ),
        (
            0xa2000021,
            Operation::Storage(StorageOperation::Store),
            Some(Qualifier::LogicalNotAssign),
        ),
        (
            0xa200003d,
            Operation::ControlFlow(ControlFlowOperation::Equal),
            None,
        ),
        (
            0xa300005e,
            Operation::ControlFlow(ControlFlowOperation::LogicalXor),
            None,
        ),
        (0xdeadbeef, Operation::Unknown, None),
    ] {
        let bytes = words(&[0xa0000000, 3, 0x80000007, 0x9000ffff, code]);
        let arg = parse(&mut BinaryReader::new(&bytes), 100, A::Command, &[])?;
        let Value::Expression(tokens) = arg.value else {
            return Err(Error::InvalidFormat);
        };
        assert_eq!(tokens.len(), 3);
        assert_eq!(
            tokens[0].opcode.operation,
            Operation::Storage(StorageOperation::Reference)
        );
        assert_eq!(tokens[0].args[0].name, A::VariableId);
        assert!(matches!(tokens[1].args[0].value, Value::Integer(-1)));
        assert_eq!(tokens[2].opcode.operation, operation);
        assert_eq!(tokens[2].opcode.variant, qualifier);
        assert_eq!(tokens[2].opcode.code, code);
        assert_eq!(tokens[2].span.offset, 116);
        assert_eq!(tokens[2].raw, bytes[16..]);
        assert_eq!(arg.span.size, 20);
    }
    Ok(())
}
#[test]
fn scalar_dispatch_and_postfix_constant_table_have_distinct_semantics() -> Result<()> {
    let mut data = words(&[0; 21]);
    BinaryWriter::u32_le(20, &mut data[72..]);
    BinaryWriter::u32_le(0x80000001, &mut data[80..]);
    let encoded = words(&[0xa0000000, 1, 0x91000000]);
    let arg = parse(&mut BinaryReader::new(&encoded), 0, A::Value, &data)?;
    let Value::Expression(tokens) = arg.value else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(tokens[0].opcode.variant, Some(Qualifier::Constant));
    assert_eq!(tokens[0].args[0].name, A::ConstantIndex);
    assert!(matches!(tokens[0].args[1].value, Value::DataAddress(80)));
    assert!(matches!(
        tokens[0].args[2].value,
        Value::Integer(-2147483647)
    ));
    assert_eq!(tokens[0].args[2].span.size, 0);
    let scalar = words(&[0x91000000]);
    let arg = parse(&mut BinaryReader::new(&scalar), 0, A::Value, &[])?;
    let Value::Expression(tokens) = arg.value else {
        return Err(Error::InvalidFormat);
    };
    assert!(matches!(tokens[0].args[0].value, Value::Integer(0)));
    for code in [0xc0000123, 0xd0000456] {
        let scalar = words(&[code]);
        let arg = parse(&mut BinaryReader::new(&scalar), 0, A::Value, &[])?;
        let Value::Expression(tokens) = arg.value else {
            return Err(Error::InvalidFormat);
        };
        assert!(
            matches!(tokens[0].args[0].value, Value::Unsigned(value) if value == u64::from(code))
        );
    }
    Ok(())
}
#[test]
fn unknown_scalar_layout_and_truncated_frames_do_not_shift_arguments() {
    for values in [
        &[0xeeeeeeee][..],
        &[0xa0000000],
        &[0xa0000000, 2, 0x90000001],
        &[0xa0000000, u32::MAX],
    ] {
        let bytes = words(values);
        assert!(parse(&mut BinaryReader::new(&bytes), 0, A::Value, &[]).is_err());
    }
}
