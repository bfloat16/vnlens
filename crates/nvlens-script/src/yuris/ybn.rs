//! YSTB 0x1EE disassembly, verified at 0x452299 (sections/instructions),
//! 0x429E7D (12-byte operands), 0x446044 (conditional targets), and 0x45D83C
//! (YSCM command definitions). The four XOR sections restart independently.

use super::{expression, tables};
use crate::ir::*;
use nvlens_core::{Error, ResourceResolver, Result};
use nvlens_io::BinaryReader;

pub(super) fn corrupt(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
pub(super) fn attribute(name: &str, value: impl Into<u64>) -> Attribute {
    Attribute {
        name: name.into(),
        value: value.into(),
    }
}
pub(super) fn operand(name: impl Into<String>, span: Span, value: Value) -> Operand {
    Operand {
        name: name.into(),
        span,
        value,
        attributes: Vec::new(),
    }
}
pub(super) fn opcode(code: u32, name: Option<String>) -> Opcode {
    Opcode {
        namespace: "yuris".into(),
        code,
        mnemonic: name,
    }
}

pub(super) fn section(name: &str, data: &[u8], range: std::ops::Range<usize>) -> Section {
    Section {
        name: name.into(),
        span: Span {
            offset: range.start as u64,
            size: range.len() as u64,
        },
        raw: data[range].to_vec(),
    }
}

fn sections(data: &[u8]) -> Result<(usize, Vec<std::ops::Range<usize>>)> {
    let mut reader = BinaryReader::new(data);
    if reader.read_bytes(4)? != b"YSTB" {
        return Err(Error::InvalidFormat);
    }
    let version = reader.read_u32_le()?;
    if version != 0x1ee {
        return Err(Error::Unsupported(format!("YSTB version 0x{version:X}")));
    }
    let count = reader.read_u32_le()? as usize;
    let mut start = 32usize;
    let mut sections = Vec::with_capacity(4);
    for _ in 0..4 {
        let size = reader.read_u32_le()? as usize;
        let end = start
            .checked_add(size)
            .filter(|&end| end <= data.len())
            .ok_or_else(|| corrupt(start, "YSTB section exceeds file"))?;
        sections.push(start..end);
        start = end;
    }
    reader.read_u32_le()?;
    if start != data.len() {
        return Err(corrupt(start, "YSTB section sizes do not cover file"));
    }
    if count.checked_mul(4) != Some(sections[0].len())
        || sections[3].len() != sections[0].len()
        || !sections[1].len().is_multiple_of(12)
    {
        return Err(corrupt(
            8,
            "YSTB instruction, operand, or source-line table size mismatch",
        ));
    }
    Ok((count, sections))
}

pub fn decrypt_ystb(data: &mut [u8], key: &[u8; 4]) -> Result<()> {
    let (_, ranges) = sections(data)?;
    for range in ranges {
        nvlens_crypto::cipher::xor::apply_u32_key(&mut data[range], key);
    }
    Ok(())
}

pub(super) fn c_string(reader: &mut BinaryReader<'_>) -> Result<String> {
    let offset = reader.position();
    let mut bytes = Vec::new();
    loop {
        let byte = reader.read_u8()?;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
    }
    expression::text(&bytes, offset as u64)
}

pub fn disassemble(data: &[u8], resources: Option<&dyn ResourceResolver>) -> Result<Script> {
    let mut header = BinaryReader::new(data);
    let magic = header.read_bytes(4)?;
    let version = header.read_u32_le()?;
    if version != 0x1ee {
        return Err(Error::Unsupported(format!("YBN version 0x{version:X}")));
    }
    let mut script = Script {
        ir_version: 2,
        format: "ybn/yuris".into(),
        format_version: version,
        sections: Vec::new(),
        instructions: Vec::new(),
    };
    if magic != b"YSTB" {
        return tables::disassemble(data, script);
    }
    let (count, ranges) = sections(data)?;
    script.sections.push(section("header", data, 0..32));
    for (name, range) in ["instructions", "operands", "data", "source_lines"]
        .iter()
        .zip(&ranges)
    {
        script.sections.push(section(name, data, range.clone()));
    }
    let definitions = if let Some(resources) = resources {
        resources
            .read_resource("ysbin/ysc.ybn")?
            .map(|bytes| tables::commands(&bytes).map(|v| v.0))
            .transpose()?
    } else {
        None
    };
    let mut code = BinaryReader::new(&data[ranges[0].clone()]);
    let mut params = BinaryReader::new(&data[ranges[1].clone()]);
    let values = &data[ranges[2].clone()];
    let mut lines = BinaryReader::new(&data[ranges[3].clone()]);
    let mut labels = None;
    script.instructions.reserve(count);
    for id in 0..count {
        let op = code.read_u8()?;
        let argc = code.read_u8()?;
        let flags = code.read_u8()?;
        let reserved = code.read_u8()?;
        let definition = definitions
            .as_ref()
            .and_then(|defs| defs.get(usize::from(op)));
        let mut instruction = Instruction {
            id: id as u64,
            span: Span {
                offset: (32 + id * 4) as u64,
                size: 4,
            },
            source_line: Some(lines.read_u32_le()?),
            opcode: opcode(u32::from(op), definition.map(|d| d.name.clone())),
            operands: Vec::with_capacity(usize::from(argc)),
            attributes: vec![attribute("flags", flags), attribute("reserved", reserved)],
        };
        for arg_index in 0..argc {
            let start = ranges[1].start + params.position();
            let arg = params.read_u8()?;
            let flags = params.read_u8()?;
            let ty = params.read_u8()?;
            let operator = params.read_u8()?;
            let length = params.read_u32_le()?;
            let offset = params.read_u32_le()?;
            let span = Span {
                offset: start as u64,
                size: 12,
            };
            let is_control = (matches!(op, 11 | 45 | 46 | 56) && arg_index > 0) || op == 79;
            let argument = definition.and_then(|d| d.arguments.get(usize::from(arg)));
            if op == 54 && arg_index == 0 {
                let operation = match operator {
                    0 => "LET.assign",
                    1 => "LET.add",
                    2 => "LET.subtract",
                    3 => "LET.multiply",
                    4 => "LET.divide",
                    5 => "LET.remainder",
                    6 => "LET.bitwise_and",
                    7 => "LET.bitwise_or",
                    8 => "LET.bitwise_xor",
                    _ => "LET.unknown",
                };
                instruction.opcode.mnemonic = Some(operation.into());
            }
            let name = if is_control {
                match (op, arg_index) {
                    (79, _) => "return_code".into(),
                    (45, 1) | (11, 1) => "next_branch".into(),
                    (45, 2) | (56, 1) => "end".into(),
                    _ => format!("control_{arg_index}"),
                }
            } else if let Some(name) = positional_name(op, arg_index) {
                name.into()
            } else {
                argument
                    .map(|a| a.name.clone())
                    .unwrap_or_else(|| format!("arg_{arg}"))
            };
            let value = if is_control {
                if op != 79 && length as usize > count {
                    return Err(corrupt(
                        start + 4,
                        "Control target exceeds instruction stream",
                    ));
                }
                Value::Fields(vec![
                    operand(
                        if op == 79 { "id" } else { "descriptor" },
                        Span {
                            offset: start as u64,
                            size: 4,
                        },
                        Value::Unsigned(u64::from(BinaryReader::u32_le(&data[start..]))),
                    ),
                    operand(
                        if op == 79 { "metadata" } else { "target" },
                        Span {
                            offset: start as u64 + 4,
                            size: 4,
                        },
                        if op == 79 {
                            Value::Unsigned(u64::from(length))
                        } else {
                            Value::InstructionTarget(u64::from(length))
                        },
                    ),
                    operand(
                        "data_offset",
                        Span {
                            offset: start as u64 + 8,
                            size: 4,
                        },
                        Value::Unsigned(u64::from(offset)),
                    ),
                ])
            } else {
                let end = (offset as usize)
                    .checked_add(length as usize)
                    .filter(|&end| end <= values.len())
                    .ok_or_else(|| corrupt(start, "Operand data range exceeds value section; script may still be encrypted"))?;
                let raw = &values[offset as usize..end];
                let address = (ranges[2].start + offset as usize) as u64;
                if ty == 0 && matches!(op, 106 | 110) {
                    Value::Text(expression::text(raw, address)?)
                } else if ty <= 4 {
                    Value::Expression(expression::decode(raw, address)?)
                } else {
                    Value::Bytes(raw.to_vec())
                }
            };
            let mut attributes = vec![
                attribute("id", arg),
                attribute("flags", flags),
                attribute("type", ty),
                attribute("operator", operator),
                attribute("length", length),
                attribute("offset", offset),
            ];
            if !is_control
                && positional_name(op, arg_index).is_none()
                && let Some(argument) = argument
            {
                attributes.push(attribute("declared_kind", argument.kind));
                attributes.push(attribute("conversion_rule", argument.rule));
            }
            instruction.operands.push(Operand {
                name,
                span,
                value,
                attributes,
            });
            if matches!(op, 43 | 44)
                && arg == 0
                && let Some(Value::Expression(tokens)) =
                    instruction.operands.last().map(|p| &p.value)
                && let [token] = tokens.as_slice()
                && token.opcode.code == u32::from(b'M')
                && let Some(Value::Text(name)) = &token.value
                && let Some(resources) = resources
            {
                if labels.is_none() {
                    labels = Some(
                        resources
                            .read_resource("ysbin/ysl.ybn")?
                            .map(|bytes| tables::labels(&bytes))
                            .transpose()?,
                    );
                }
                if let Some(Some(labels)) = &labels
                    && let Some(label) = labels.iter().find(|label| label.name == *name)
                {
                    instruction.operands.push(operand(
                        "resolved_target",
                        span,
                        Value::ResourceInstructionTarget {
                            resource: format!("ysbin/yst{:05}.ybn", label.script),
                            instruction: u64::from(label.instruction),
                            symbol: label.name.clone(),
                        },
                    ));
                }
            }
        }
        script.instructions.push(instruction);
    }
    if params.remaining() != 0 {
        return Err(corrupt(
            ranges[1].start + params.position(),
            "Unclaimed operand records",
        ));
    }
    Ok(script)
}

fn positional_name(op: u8, index: u8) -> Option<&'static str> {
    match (op, index) {
        (11 | 45, 0) => Some("condition"),
        (54, 0) => Some("destination"),
        (54, 1) => Some("value"),
        (17..=19 | 26 | 51 | 80..=82 | 90, 0) => Some("variable"),
        (17..=19 | 26 | 51 | 80..=82 | 90, 1) => Some("initial"),
        (43, 0) => Some("label"),
        (106, 0) => Some("text"),
        (110, 0) => Some("value"),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;

    fn fixture() -> Vec<u8> {
        let mut b = vec![0; 32];
        b[..4].copy_from_slice(b"YSTB");
        for (at, value) in [(4, 0x1ee), (8, 2), (12, 8), (16, 12), (20, 8), (24, 8)] {
            BinaryWriter::u32_le(value, &mut b[at..]);
        }
        b.extend_from_slice(&[106, 1, 0, 0, 255, 0, 7, 0]);
        let mut param = [0; 12];
        BinaryWriter::u32_le(8, &mut param[4..]);
        b.extend_from_slice(&param);
        b.extend_from_slice(b"Example!");
        for line in [12, 13] {
            let mut word = [0; 4];
            BinaryWriter::u32_le(line, &mut word);
            b.extend_from_slice(&word);
        }
        b
    }

    #[test]
    fn xor_sections_and_lossless_unknown_instructions() {
        let bytes = fixture();
        let key = [1, 2, 3, 4];
        let mut encrypted = bytes.clone();
        decrypt_ystb(&mut encrypted, &key).unwrap();
        assert_ne!(encrypted, bytes);
        assert!(disassemble(&encrypted, None).is_err());
        decrypt_ystb(&mut encrypted, &key).unwrap();
        assert_eq!(encrypted, bytes);
        let ir = disassemble(&bytes, None).unwrap();
        assert_eq!(ir.instructions.len(), 2);
        assert_eq!(ir.instructions[1].opcode.code, 255);
        assert!(ir.instructions[1].opcode.mnemonic.is_none());
        assert!(matches!(&ir.instructions[0].operands[0].value,Value::Text(s) if s=="Example!"));
        assert!(
            ir.instructions[0]
                .disassembly()
                .starts_with("00000020  L12")
        );
        assert_eq!(
            ir.sections
                .iter()
                .flat_map(|section| section.raw.iter().copied())
                .collect::<Vec<_>>(),
            bytes
        );
        assert!(
            String::from_utf8(ir.to_json().unwrap())
                .unwrap()
                .contains("instruction")
        );
        for end in 0..bytes.len() {
            assert!(disassemble(&bytes[..end], None).is_err());
        }
    }

    #[test]
    fn type_four_expressions_and_labels_are_resolved_only_when_referenced() {
        use std::cell::RefCell;
        struct Resources {
            calls: RefCell<Vec<String>>,
            labels: Vec<u8>,
        }
        impl ResourceResolver for Resources {
            fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
                self.calls.borrow_mut().push(name.into());
                Ok((name == "ysbin/ysl.ybn").then(|| self.labels.clone()))
            }
        }
        let mut label = vec![0; 12 + 1024];
        label[..4].copy_from_slice(b"YSLB");
        BinaryWriter::u32_le(0x1ee, &mut label[4..]);
        BinaryWriter::u32_le(1, &mut label[8..]);
        label.extend_from_slice(b"\x03abc");
        let at = label.len();
        label.resize(at + 12, 0);
        BinaryWriter::u32_le(0x1357_7c9b, &mut label[at..]);
        BinaryWriter::u32_le(42, &mut label[at + 4..]);
        BinaryWriter::u16_le(7, &mut label[at + 8..]);
        let resources = Resources {
            calls: RefCell::new(Vec::new()),
            labels: label,
        };
        let mut bytes = fixture();
        bytes[32] = 44;
        bytes[42] = 4;
        bytes[52..60].copy_from_slice(b"M\x05\x00\"abc\"");
        let ir = disassemble(&bytes, Some(&resources)).unwrap();
        assert!(
            matches!(&ir.instructions[0].operands[0].value, Value::Expression(t)
            if matches!(&t[0].value,Some(Value::Text(s)) if s == "abc"))
        );
        assert!(matches!(&ir.instructions[0].operands[1].value,
            Value::ResourceInstructionTarget { resource, instruction: 42, symbol }
            if resource == "ysbin/yst00007.ybn" && symbol == "abc"));
        assert_eq!(
            *resources.calls.borrow(),
            ["ysbin/ysc.ybn", "ysbin/ysl.ybn"]
        );
        resources.calls.borrow_mut().clear();
        disassemble(&fixture(), Some(&resources)).unwrap();
        assert_eq!(*resources.calls.borrow(), ["ysbin/ysc.ybn"]);
    }

    #[test]
    fn control_descriptors_are_not_data_slices_and_targets_are_checked() {
        let mut bytes = fixture();
        bytes[32] = 79;
        BinaryWriter::u32_le(0x12345678, &mut bytes[40..]);
        BinaryWriter::u32_le(u32::MAX, &mut bytes[44..]);
        let ir = disassemble(&bytes, None).unwrap();
        assert!(
            matches!(&ir.instructions[0].operands[0].value,Value::Fields(fields)
            if matches!(fields[0].value, Value::Unsigned(0x12345678)))
        );
        bytes[32] = 45;
        bytes[33] = 2;
        bytes[42] = 1;
        BinaryWriter::u32_le(8, &mut bytes[44..]);
        bytes[52..60].copy_from_slice(b"M\x05\x00\"abc\"");
        bytes.splice(52..52, [0; 12]);
        BinaryWriter::u32_le(24, &mut bytes[16..]);
        BinaryWriter::u32_le(1, &mut bytes[56..]);
        BinaryWriter::u32_le(u32::MAX, &mut bytes[60..]);
        assert!(disassemble(&bytes, None).is_ok());
        BinaryWriter::u32_le(3, &mut bytes[56..]);
        assert!(disassemble(&bytes, None).is_err());
    }
}
