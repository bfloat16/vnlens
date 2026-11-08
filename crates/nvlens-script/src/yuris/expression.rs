//! YU-RIS postfix expression tokens: u8 opcode, u16 LE byte length, payload.
//! Verified at 0x426744 and dispatch initialization 0x464658. Disassembly keeps
//! stack operations and unknown tokens intact rather than evaluating the VM.

use crate::ir::ArgName;
use crate::ir::Qualifier;
use crate::ir::StorageOperation;
use crate::ir::{Arg, Opcode, Operation, Span, Token, Value};
use nvlens_core::{Error, Result};
use nvlens_io::BinaryReader;

pub(super) fn decode(data: &[u8], offset: u64) -> Result<Vec<Token>> {
    let mut reader = BinaryReader::new(data);
    offset
        .checked_add(data.len() as u64)
        .ok_or_else(|| Error::Corrupt {
            offset,
            reason: "Expression address overflow".into(),
        })?;
    let mut tokens = Vec::new();
    while reader.remaining() != 0 {
        let start = reader.position();
        let code = reader.read_u8()?;
        let length = usize::from(reader.read_u16_le()?);
        let raw = reader.read_bytes(length)?;
        let address = offset + start as u64 + 3;
        let expected = match code {
            b'B' | b')' => Some(1),
            b'W' => Some(2),
            b'I' => Some(4),
            b'L' | b'F' => Some(8),
            b'H' | b'V' | b'v' => Some(3),
            _ if super::opcode::expression(code).is_some() => Some(0),
            _ => None,
        };
        if expected.is_some_and(|expected| expected != length) {
            return Err(Error::Corrupt {
                offset: address - 2,
                reason: format!("Invalid payload size for expression token 0x{code:02X}"),
            });
        }
        let (operation, variant, value) = match (code, length) {
            (b'B', 1) => (
                Operation::Storage(StorageOperation::Push),
                Some(Qualifier::Integer),
                Some(Value::Integer(BinaryReader::compact_i64_le(raw)?)),
            ),
            (b'W', 2) => (
                Operation::Storage(StorageOperation::Push),
                Some(Qualifier::Integer),
                Some(Value::Integer(i64::from(BinaryReader::i16_le(raw)))),
            ),
            (b'I', 4) => (
                Operation::Storage(StorageOperation::Push),
                Some(Qualifier::Integer),
                Some(Value::Integer(i64::from(BinaryReader::i32_le(raw)))),
            ),
            (b'L', 8) => (
                Operation::Storage(StorageOperation::Push),
                Some(Qualifier::Integer),
                Some(Value::Integer(BinaryReader::i64_le(raw))),
            ),
            (b'F', 8) => (
                Operation::Storage(StorageOperation::Push),
                Some(Qualifier::Float64),
                Some(Value::Float64Bits(BinaryReader::u64_le(raw))),
            ),
            (b'M', _) => (
                Operation::Storage(StorageOperation::Push),
                Some(Qualifier::Text),
                Some(Value::Text(string(raw, address)?)),
            ),
            (b'H' | b'V' | b'v', 3) => {
                let operation = match code {
                    b'H' => Operation::Storage(StorageOperation::Load),
                    b'V' => Operation::Storage(StorageOperation::IndexBegin),
                    _ => Operation::Storage(StorageOperation::Reference),
                };
                (
                    operation,
                    Some(Qualifier::Variable),
                    Some(Value::Group(vec![
                        Arg {
                            name: ArgName::Sigil,
                            native_name: None,
                            span: Span {
                                offset: address,
                                size: 1,
                            },
                            value: Value::Text(char::from(raw[0]).to_string()),
                            attributes: Vec::new(),
                        },
                        Arg {
                            name: ArgName::VariableId,
                            native_name: None,
                            span: Span {
                                offset: address + 1,
                                size: 2,
                            },
                            value: Value::Unsigned(u64::from(BinaryReader::u16_le(&raw[1..]))),
                            attributes: Vec::new(),
                        },
                    ])),
                )
            }
            (b')', 1) => (
                Operation::Storage(StorageOperation::IndexEnd),
                None,
                Some(Value::Unsigned(u64::from(raw[0]))),
            ),
            (_, 0) if super::opcode::expression(code).is_some() => {
                let (operation, variant) =
                    super::opcode::expression(code).unwrap_or((Operation::Unknown, None));
                (operation, variant, None)
            }
            _ => (Operation::Unknown, None, Some(Value::Bytes(raw.to_vec()))),
        };
        tokens.push(Token {
            opcode: Opcode {
                namespace: "yuris.expression".into(),
                code: u32::from(code),
                operation,
                variant,
                native_mnemonic: None,
            },
            span: Span {
                offset: offset + start as u64,
                size: (3 + length) as u64,
            },
            args: match value {
                Some(Value::Group(fields)) => fields,
                Some(value) => vec![Arg {
                    name: if operation == Operation::Unknown {
                        ArgName::Unknown(0)
                    } else if code == b')' {
                        ArgName::Index
                    } else {
                        ArgName::Value
                    },
                    native_name: None,
                    span: Span {
                        offset: address,
                        size: length as u64,
                    },
                    value,
                    attributes: Vec::new(),
                }],
                None => Vec::new(),
            },
            raw: raw.to_vec(),
        });
    }
    Ok(tokens)
}

/// Decode the quoted byte string exactly as the VM's 0x426930 handler does.
fn string(raw: &[u8], offset: u64) -> Result<String> {
    let Some(&quote) = raw.first() else {
        return Err(Error::Corrupt {
            offset,
            reason: "Missing string delimiter".into(),
        });
    };
    let mut result = Vec::new();
    let mut index = 1;
    while let Some(&byte) = raw.get(index) {
        if byte == quote {
            if index + 1 != raw.len() {
                return Err(Error::Corrupt {
                    offset: offset + index as u64,
                    reason: "Bytes after string delimiter".into(),
                });
            }
            return text(&result, offset + 1);
        }
        if byte == b'\\' {
            index += 1;
            match raw.get(index) {
                Some(b'\\') => result.push(b'\\'),
                Some(b'n') => result.push(b'\n'),
                Some(b't') => result.push(b'\t'),
                _ => continue,
            }
            index += 1;
        } else if matches!(byte, 0x81..=0x9f | 0xe0..=0xfc) {
            let pair = raw.get(index..index + 2).ok_or_else(|| Error::Corrupt {
                offset: offset + index as u64,
                reason: "Truncated CP932 character".into(),
            })?;
            result.extend_from_slice(pair);
            index += 2;
        } else {
            result.push(byte);
            index += 1;
        }
    }
    Err(Error::Corrupt {
        offset,
        reason: "Unterminated string constant".into(),
    })
}

pub(super) fn text(bytes: &[u8], offset: u64) -> Result<String> {
    encoding_rs::SHIFT_JIS
        .decode_without_bom_handling_and_without_replacement(bytes)
        .map(|s| s.into_owned())
        .ok_or_else(|| Error::Corrupt {
            offset,
            reason: "Invalid CP932 text".into(),
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;

    fn token(code: u8, raw: &[u8]) -> Vec<u8> {
        let mut bytes = vec![code, 0, 0];
        BinaryWriter::u16_le(raw.len() as u16, &mut bytes[1..]);
        bytes.extend_from_slice(raw);
        bytes
    }

    #[test]
    fn decodes_vm_strings_without_confusing_cp932_trail_bytes() {
        let raw = b"\"a\\nb\\tc\\\\d\x83\x5c\"";
        let bytes = token(b'M', raw);
        let tokens = decode(&bytes, 0x100).unwrap();
        assert!(
            matches!(&tokens[0].args.first().map(|arg| &arg.value), Some(Value::Text(s)) if s == "a\nb\tc\\dソ")
        );
        assert_eq!(tokens[0].raw, raw);
        assert_eq!(tokens[0].span.offset, 0x100);
        assert_eq!(string(b"'quote: \"'", 0).unwrap(), "quote: \"");
        // 0x426930 drops an unrecognized escape's slash and reprocesses its
        // following byte, including a closing delimiter.
        assert_eq!(string(b"\"a\\qb\"", 0).unwrap(), "aqb");
        assert_eq!(string(b"\"a\\\"", 0).unwrap(), "a");
        assert!(string(b"\"a\\", 0).is_err());
        assert!(string(b"\"unclosed", 0).is_err());
        assert!(string(b"\"closed\"extra", 0).is_err());
        assert!(string(b"\"\x83", 0).is_err());
        for end in 1..bytes.len() {
            assert!(decode(&bytes[..end], 0).is_err());
        }
    }

    #[test]
    fn identifies_variables_and_distinguishes_logical_and_bitwise_operations() {
        let mut raw = vec![b'@', 0, 0];
        BinaryWriter::u16_le(0x1234, &mut raw[1..]);
        let tokens = decode(&token(b'H', &raw), 0x80).unwrap();
        assert!(matches!(tokens[0].args[1].value, Value::Unsigned(0x1234)));
        assert_eq!(tokens[0].args[1].span.offset, 0x84);
        for (code, name) in [
            (b'!', "not_equal"),
            (b'&', "logical_and"),
            (b'|', "logical_or"),
            (b'A', "bit_and"),
            (b'O', "bit_or"),
            (b'R', "negate"),
            (b'S', "less_equal"),
            (b'Z', "greater_equal"),
        ] {
            assert_eq!(
                decode(&token(code, &[]), 0).unwrap()[0]
                    .opcode
                    .operation
                    .name(),
                name
            );
        }
        assert!(decode(&token(b'H', &[1, 2]), 0).is_err());
        assert!(decode(&token(b'+', &[1]), 0).is_err());
        let unknown = decode(&token(0xfe, &[1, 2]), 0).unwrap();
        assert_eq!(unknown[0].opcode.operation, Operation::Unknown);
        assert_eq!(unknown[0].raw, [1, 2]);
    }

    #[test]
    fn keeps_signed_constants_and_exact_float_bits() {
        let signed = decode(&token(b'B', &[0xff]), 0).unwrap();
        assert!(matches!(
            signed[0].args.first().map(|arg| &arg.value),
            Some(Value::Integer(-1))
        ));
        let bits = 0x7ff8_0000_0000_0042;
        let mut raw = [0; 8];
        BinaryWriter::u64_le(bits, &mut raw);
        assert!(
            matches!(decode(&token(b'F', &raw), 0).unwrap()[0].args.first().map(|arg| &arg.value), Some(Value::Float64Bits(v)) if *v == bits)
        );
    }
}
