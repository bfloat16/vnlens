//! ExHIBIT RLD v0-v3, verified against RetouchSystem::loadRld/liteLoad and
//! CMD_DATA reader. LE command words encode ID:u16, integer count:u8,
//! string count:4 bits, variant:4 bits. Strings are zero-terminated CP932.
//! Version 1+ adds a u32 and a 256-byte companion-name field to the header.

use super::opcode;
use crate::ir::{self, Arg, ArgName, Attribute, Instruction, Script, Section, Span, Value};
use nvlens_core::{ArchiveOptions, Error, Result};
use nvlens_io::{BinaryReader, BinaryWriter};
use std::borrow::Cow;

pub(super) fn decode<'a>(data: &'a [u8], options: &ArchiveOptions) -> Result<Cow<'a, [u8]>> {
    if !data.starts_with(b"\0DLR") {
        return Ok(Cow::Borrowed(data));
    }
    let mut r = BinaryReader::new_at(data, 4)?;
    let version = r.read_u32_le()?;
    if version > 3 {
        return Err(Error::Unsupported(format!("RLD version {version}")));
    }
    if version < 3 {
        return Ok(Cow::Borrowed(data));
    }
    r.read_bytes(8)?;
    // RLD does not record the caller's system-resource flag. Both keys
    // come from engine identification; accept only a complete command
    // stream. Versions 2 and 3 share the same record layout; version 3
    // additionally triggers loadRld's encryption step.
    let mut accepted = None;
    let mut first_error = None;
    for name in ["exhibit_rld", "exhibit_rld_system"] {
        let Some(key) = options.keys.get(name) else {
            continue;
        };
        let seed = BinaryReader::new(key.bytes()).read_u32_le()?;
        let mut decoded = data.to_vec();
        nvlens_crypto::cipher::exhibit::apply_rld(&mut decoded[16..], seed);
        match complete(&decoded) {
            Ok(()) => {
                // Mark the decoded export as the native plaintext variant
                // so a later open does not decrypt the same bytes twice.
                BinaryWriter::u32_le(2, &mut decoded[4..8]);
                if accepted.as_ref().is_some_and(|old| old != &decoded) {
                    return Err(Error::UnknownScheme(Some(
                        "Ambiguous RLD resource parameters".into(),
                    )));
                }
                accepted = Some(decoded);
            }
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }
    accepted.map(Cow::Owned).ok_or_else(|| {
        first_error.unwrap_or_else(|| {
            Error::UnknownScheme(Some("ExHIBIT RLD parameters are missing".into()))
        })
    })
}

fn complete(data: &[u8]) -> Result<()> {
    let parsed = parse(data)?;
    if parsed.sections.last().is_some_and(|s| s.name == "trailing") {
        return Err(Error::Corrupt {
            offset: data.len() as u64,
            reason: "RLD command count leaves trailing data".into(),
        });
    }
    Ok(())
}

pub(super) fn parse(data: &[u8]) -> Result<Script> {
    let mut r = BinaryReader::new_at(data, 4)?;
    let version = r.read_u32_le()?;
    if version > 3 {
        return Err(Error::Unsupported(format!("RLD version {version}")));
    }
    let _header_size = r.read_u32_le()?;
    let count = r.read_u32_le()?;
    if version != 0 {
        let companions = r.read_u32_le()?;
        let names = r.read_bytes(256)?;
        let end = names.iter().position(|&b| b == 0).unwrap_or(names.len());
        let names = &names[..end];
        let available = if names.is_empty() {
            0
        } else {
            names.split(|&b| b == b',').count()
        };
        if companions as usize > available {
            return Err(Error::Corrupt {
                offset: 16,
                reason: "RLD companion count exceeds its name list".into(),
            });
        }
    }
    let header_end = r.position();
    let mut instructions = Vec::new();
    for id in 0..count {
        let start = r.position();
        let word = r.read_u32_le()?;
        let code = word as u16;
        let numbers = (word >> 16) & 255;
        let strings = (word >> 24) & 15;
        let variant = word >> 28;
        // CMD_DATA has 21 integer and 10 string slots; its readers consume
        // at most these counts, so larger encodings cannot form a stream.
        if numbers > 21 || strings > 10 {
            return Err(Error::Corrupt {
                offset: start as u64,
                reason: "RLD operand count exceeds CMD_DATA layout".into(),
            });
        }
        let mut args = Vec::new();
        for i in 0..numbers {
            let offset = r.position();
            args.push(Arg {
                name: opcode::number_arg(code, variant, i),
                native_name: None,
                span: Span {
                    offset: offset as u64,
                    size: 4,
                },
                value: Value::Integer(i64::from(r.read_u32_le()? as i32)),
                attributes: vec![Attribute {
                    name: "operand_id".into(),
                    value: u64::from(i),
                }],
            });
        }
        for i in 0..strings {
            let offset = r.position();
            while r.read_u8()? != 0 {}
            let bytes = &data[offset..r.position() - 1];
            let (text, _, errors) = encoding_rs::SHIFT_JIS.decode(bytes);
            let value = if errors {
                Value::Bytes(bytes.to_vec())
            } else {
                Value::Text(text.into_owned())
            };
            args.push(Arg {
                name: opcode::string_arg(code, variant, numbers, i),
                native_name: None,
                span: Span {
                    offset: offset as u64,
                    size: (r.position() - offset) as u64,
                },
                value,
                attributes: vec![Attribute {
                    name: "operand_id".into(),
                    value: u64::from(numbers + i),
                }],
            });
        }
        instructions.push(Instruction {
            id: u64::from(id),
            span: Span {
                offset: start as u64,
                size: (r.position() - start) as u64,
            },
            source_line: None,
            opcode: opcode::opcode(code),
            args,
            attributes: vec![
                Attribute {
                    name: "command_word".into(),
                    value: u64::from(word),
                },
                Attribute {
                    name: "variant".into(),
                    value: u64::from(variant),
                },
            ],
        });
    }
    resolve_labels(&mut instructions);
    let end = r.position();
    let mut sections = vec![
        Section {
            name: "header".into(),
            span: Span {
                offset: 0,
                size: header_end as u64,
            },
            raw: data[..header_end].to_vec(),
        },
        Section {
            name: "commands".into(),
            span: Span {
                offset: header_end as u64,
                size: (end - header_end) as u64,
            },
            raw: data[header_end..end].to_vec(),
        },
    ];
    if end < data.len() {
        sections.push(Section {
            name: "trailing".into(),
            span: Span {
                offset: end as u64,
                size: (data.len() - end) as u64,
            },
            raw: data[end..].to_vec(),
        });
    }
    Ok(Script {
        ir_version: ir::VERSION,
        format: "RLD/ExHIBIT".into(),
        format_version: version,
        sections,
        instructions,
    })
}

// RetouchSystem::blockId2Index searches block/CMD_FUNC markers in order.
// Dynamic block expressions cannot be resolved from their encoded integers.
fn resolve_labels(instructions: &mut [Instruction]) {
    let mut labels = std::collections::BTreeMap::new();
    let mut block = Some(0i64);
    let mut uncertain = false;
    for instruction in instructions.iter() {
        match instruction.opcode.code {
            5 => {
                block = instruction
                    .args
                    .first()
                    .filter(|o| o.name == ArgName::LabelId)
                    .and_then(|o| {
                        if let Value::Integer(value) = o.value {
                            if value == -1 {
                                block.and_then(|old| old.checked_add(1))
                            } else {
                                Some(value)
                            }
                        } else {
                            None
                        }
                    });
                if let Some(label) = block {
                    if !uncertain {
                        labels.entry(label).or_insert(instruction.id);
                    }
                } else {
                    // An earlier unresolved marker can shadow any later label.
                    uncertain = true;
                }
            }
            47 => {
                if let Some(Arg {
                    value: Value::Integer(label),
                    ..
                }) = instruction.args.first()
                    && !uncertain
                {
                    labels.entry(*label).or_insert(instruction.id);
                }
            }
            _ => {}
        }
    }
    for instruction in instructions {
        if matches!(instruction.opcode.code, 20 | 22)
            && let Some(operand) = instruction.args.first()
            && operand.name == ArgName::LabelId
            && let Value::Integer(label) = operand.value
            && let Some(target) = labels
                .get(&label)
                .copied()
                .or((label == 0 && !uncertain).then_some(0))
        {
            instruction.args.push(Arg {
                name: ArgName::ResolvedTarget,
                native_name: None,
                span: Span {
                    offset: operand.span.offset,
                    size: 0,
                },
                value: Value::InstructionTarget(target),
                attributes: Vec::new(),
            });
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::Rld;
    use super::*;
    use crate::ScriptFormat;
    use crate::ir::{Operation, TextOperation};
    use nvlens_core::Secret;

    fn fixture() -> Vec<u8> {
        let mut data = vec![0; 276];
        for (i, word) in [0x524c_4400, 3, 272, 1].into_iter().enumerate() {
            BinaryWriter::u32_le(word, &mut data[i * 4..]);
        }
        let mut word = [0; 4];
        BinaryWriter::u32_le(0x1101_001c, &mut word);
        data.extend(word);
        BinaryWriter::u32_le(u32::MAX, &mut word);
        data.extend(word);
        data.extend([0x82, 0xa0, 0]);
        data
    }

    #[test]
    fn system_and_game_parameters_decode_to_reopenable_lossless_ir() {
        let mut options = ArchiveOptions::default();
        for (name, seed) in [("exhibit_rld", 1), ("exhibit_rld_system", 7)] {
            let mut bytes = vec![0; 4];
            BinaryWriter::u32_le(seed, &mut bytes);
            options.keys.insert(name, Secret::new(bytes));
        }
        for seed in [1, 7] {
            let mut encrypted = fixture();
            nvlens_crypto::cipher::exhibit::apply_rld(&mut encrypted[16..], seed);
            let decoded = Rld.decode(&encrypted, &options).unwrap();
            assert_eq!(Rld.decode(&decoded, &options).unwrap(), decoded);
            let script = Rld.disassemble(&decoded, None).unwrap().unwrap();
            assert_eq!(
                script.instructions[0].opcode.operation,
                Operation::Text(TextOperation::Show)
            );
            assert!(matches!(&script.instructions[0].args[1].value, Value::Text(s) if s == "あ"));
            assert_eq!(
                script
                    .sections
                    .iter()
                    .flat_map(|s| s.raw.iter().copied())
                    .collect::<Vec<_>>(),
                &*decoded
            );
            assert!(
                Rld.decode(&encrypted[..encrypted.len() - 1], &options)
                    .is_err()
            );
            assert!(Rld.decode(&encrypted, &ArchiveOptions::default()).is_err());
            let mut empty = fixture();
            empty.truncate(276);
            BinaryWriter::u32_le(0, &mut empty[12..16]);
            let mut expected = empty.clone();
            BinaryWriter::u32_le(2, &mut expected[4..8]);
            nvlens_crypto::cipher::exhibit::apply_rld(&mut empty[16..], seed);
            assert_eq!(&*Rld.decode(&empty, &options).unwrap(), expected);
        }
        assert!(Rld.disassemble(b"unrelated", None).unwrap().is_none());
    }

    #[test]
    fn unknown_commands_and_invalid_text_preserve_source_values() {
        let mut data = fixture();
        BinaryWriter::u32_le(0x0100_ffff, &mut data[276..]);
        data.truncate(280);
        data.extend([0x81, 0]);
        let script = parse(&data).unwrap();
        assert_eq!(script.instructions[0].opcode.operation, Operation::Unknown);
        assert!(matches!(&script.instructions[0].args[0].value, Value::Bytes(b) if b == &[0x81]));
    }
}
