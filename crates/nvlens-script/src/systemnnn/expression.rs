//! CScript expression VM at 0x45d3c0, reference resolver at 0x45dc80.
//! Postfix operands remain ordered: variable words are deferred references,
//! and assignment operators consume references from the implicit VM stack.
//! A standalone value uses the VM's high-nibble dispatch, whereas postfix
//! resolution uses its high-16-bit tags. These are intentionally distinct.
use super::{
    opcode,
    spt::{arg, byte_offset, unsigned, word},
};
use crate::ir::{
    Arg, ArgName as A, Attribute, Operation, Qualifier, StorageOperation, Token, Value,
};
use nvlens_core::{Error, Result};
use nvlens_io::BinaryReader;

pub(super) fn parse(r: &mut BinaryReader<'_>, base: usize, name: A, data: &[u8]) -> Result<Arg> {
    let start = r.position();
    let bytes = r.read_bytes(4)?;
    let code = BinaryReader::u32_le(bytes);
    let mut tokens = Vec::new();
    let mut attributes = Vec::new();
    if code == 0xa0000000 {
        let count = r.read_u32_le()?;
        attributes.push(Attribute {
            name: "token_count".into(),
            value: u64::from(count),
        });
        let encoded = r.read_bytes(byte_offset(count)?)?;
        for (index, bytes) in encoded.as_chunks::<4>().0.iter().enumerate() {
            tokens.push(token(
                BinaryReader::u32_le(bytes),
                base + start + 8 + index * 4,
                bytes,
                true,
                data,
            )?);
        }
    } else if matches!(
        code & 0xf0000000,
        0x80000000 | 0x90000000 | 0xc0000000 | 0xd0000000
    ) {
        tokens.push(token(code, base + start, bytes, false, data)?);
    } else {
        // Other words enter the VM's framed-expression path. Without a
        // verified encoding, treating them as one word would shift args.
        return Err(Error::Unsupported(format!(
            "Unknown SystemNNN expression encoding at {:#x}",
            base + start
        )));
    }
    let mut value = arg(
        name,
        base + start,
        r.position() - start,
        Value::Expression(tokens),
    );
    value.attributes = attributes;
    Ok(value)
}

fn token(code: u32, at: usize, bytes: &[u8], postfix: bool, data: &[u8]) -> Result<Token> {
    let mut opcode = opcode::token(code);
    let tag = if postfix {
        code & 0xffff0000
    } else {
        code & 0xf0000000
    };
    let args = match tag {
        0x80000000 if postfix => {
            opcode.operation = Operation::Storage(StorageOperation::Reference);
            opcode.variant = Some(Qualifier::Variable);
            vec![unsigned(A::VariableId, at, code & 0xffff)]
        }
        0x80000000 => {
            opcode.operation = Operation::Storage(StorageOperation::Load);
            opcode.variant = Some(Qualifier::Variable);
            vec![unsigned(A::VariableId, at, code & 0xffff)]
        }
        0x90000000 => {
            opcode.operation = Operation::Storage(StorageOperation::Push);
            opcode.variant = Some(Qualifier::Integer);
            vec![arg(A::Value, at, 4, Value::Integer(i64::from(code as i16)))]
        }
        0x91000000 => {
            opcode.operation = Operation::Storage(StorageOperation::Load);
            opcode.variant = Some(Qualifier::Constant);
            let index = code & 0xffff;
            let table = byte_offset(word(data, 18)?)?;
            let offset = table
                .checked_add(byte_offset(index)?)
                .ok_or(Error::Corrupt {
                    offset: at as u64,
                    reason: "SPT constant offset overflow".into(),
                })?;
            let value = BinaryReader::new_at(data, offset)?.read_u32_le()? as i32;
            vec![
                unsigned(A::ConstantIndex, at, index),
                arg(A::DataOffset, at, 0, Value::DataAddress(offset as u64)),
                arg(A::Value, at, 0, Value::Integer(i64::from(value))),
            ]
        }
        0x92000000 => {
            opcode.operation = Operation::Storage(StorageOperation::Load);
            opcode.variant = Some(Qualifier::Register);
            vec![unsigned(A::Register, at, code & 0xffff)]
        }
        0xc0000000 | 0xd0000000 if !postfix => {
            opcode.operation = Operation::Storage(StorageOperation::Push);
            opcode.variant = Some(Qualifier::Immediate);
            vec![unsigned(A::Value, at, code)]
        }
        _ if opcode.operation == Operation::Unknown => vec![unsigned(A::Unknown(0), at, code)],
        _ => Vec::new(),
    };
    Ok(Token {
        opcode,
        span: crate::ir::Span {
            offset: at as u64,
            size: 4,
        },
        args,
        raw: bytes.to_vec(),
    })
}

#[cfg(test)]
mod tests {
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
}
