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
#[path = "../../tests/yuris/expression.rs"]
mod tests;
