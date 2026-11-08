//! YU-RIS 0x1EE auxiliary tables, from the engine loaders at 0x45D83C
//! (YSCM), 0x45DEFC (YSTD), 0x45E15C (YSTL), 0x45E45C (YSCF),
//! 0x45E97C (YSLB), and variable initialization at 0x45293C (YSVR).
//! Table headers differ; record boundaries are not inferred from a shared header.

use super::{attribute, c_string, corrupt, expression, opcode, operand, section};
use crate::ir::DataOperation;
use crate::ir::*;
use nvlens_core::{Error, Result};
use nvlens_io::BinaryReader;

#[derive(Debug)]
pub(super) struct Argument {
    pub name: String,
    pub kind: u8,
    pub rule: u8,
    span: Span,
}

#[derive(Debug)]
pub(super) struct Command {
    pub name: String,
    pub arguments: Vec<Argument>,
    span: Span,
}

#[derive(Debug)]
pub(super) struct Label {
    pub name: String,
    pub instruction: u32,
    pub script: u16,
}

/// Reads the YSTL source-path mapping using the same parser as disassembly.
/// IDs refer to `ysbin/yst%05d.ybn` (engine loader 0x452299), not record order.
pub fn script_paths(data: &[u8]) -> Result<Vec<(u32, String)>> {
    if !data.starts_with(b"YSTL") {
        return Err(corrupt(0, "Script path table is not YSTL"));
    }
    let table = super::ybn::disassemble(data, None)?;
    Ok(table
        .instructions
        .into_iter()
        .filter_map(|record| {
            record.args.into_iter().find_map(|field| match field.value {
                Value::Text(path) if field.name == ArgName::SourcePath => {
                    Some((record.opcode.code, path))
                }
                _ => None,
            })
        })
        .collect())
}

pub(super) fn labels(data: &[u8]) -> Result<Vec<Label>> {
    // Reuse the complete table parser so companion reads receive identical validation.
    let table = super::ybn::disassemble(data, None)?;
    if !data.starts_with(b"YSLB") {
        return Err(corrupt(0, "Companion label table is not YSLB"));
    }
    let mut result = Vec::new();
    for record in table
        .instructions
        .iter()
        .filter(|record| record.opcode.variant == Some(Qualifier::Label))
    {
        let mut label = Label {
            name: String::new(),
            instruction: 0,
            script: 0,
        };
        for field in &record.args {
            match (field.name, &field.value) {
                (ArgName::Name, Value::Text(name)) => label.name = name.clone(),
                (ArgName::Instruction, Value::InstructionTarget(target)) => {
                    label.instruction = *target as u32
                }
                (ArgName::ScriptId, Value::Unsigned(id)) => label.script = *id as u16,
                _ => {}
            }
        }
        result.push(label);
    }
    Ok(result)
}

pub(super) fn commands(data: &[u8]) -> Result<(Vec<Command>, usize)> {
    let mut r = BinaryReader::new(data);
    if r.read_bytes(4)? != b"YSCM" {
        return Err(corrupt(0, "Companion command table is not YSCM"));
    }
    let version = r.read_u32_le()?;
    if version != 0x1ee {
        return Err(Error::Unsupported(format!("YSCM version 0x{version:X}")));
    }
    let count = r.read_u32_le()? as usize;
    r.read_u32_le()?;
    if count > r.remaining() / 2 {
        return Err(corrupt(8, "Command count exceeds table"));
    }
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let start = r.position();
        let name = c_string(&mut r)?;
        let count = usize::from(r.read_u8()?);
        if count > r.remaining() / 3 {
            return Err(corrupt(r.position(), "Argument count exceeds table"));
        }
        let mut arguments = Vec::with_capacity(count);
        for _ in 0..count {
            let start = r.position();
            let name = c_string(&mut r)?;
            arguments.push(Argument {
                name,
                kind: r.read_u8()?,
                rule: r.read_u8()?,
                span: Span {
                    offset: start as u64,
                    size: (r.position() - start) as u64,
                },
            });
        }
        result.push(Command {
            name,
            arguments,
            span: Span {
                offset: start as u64,
                size: (r.position() - start) as u64,
            },
        });
    }
    Ok((result, r.position()))
}

/// Collect typed fields with their exact source spans while walking each record.
struct Record<'a> {
    reader: BinaryReader<'a>,
    start: usize,
    fields: Vec<Arg>,
    namespace: String,
}
impl<'a> Record<'a> {
    fn new(data: &'a [u8], offset: usize) -> Result<Self> {
        Ok(Self {
            reader: BinaryReader::new_at(data, offset)?,
            start: offset,
            fields: Vec::new(),
            namespace: format!(
                "yuris.table.{}",
                String::from_utf8_lossy(&data[..4]).to_ascii_lowercase()
            ),
        })
    }
    fn field(&mut self, name: ArgName, start: usize, value: Value) {
        self.fields.push(operand(
            name,
            Span {
                offset: start as u64,
                size: (self.reader.position() - start) as u64,
            },
            value,
        ));
    }
    fn unsigned(&mut self, name: ArgName, size: usize) -> Result<u64> {
        let start = self.reader.position();
        let value = BinaryReader::compact_u64_le(self.reader.read_bytes(size)?)?;
        self.field(name, start, Value::Unsigned(value));
        Ok(value)
    }
    fn text(&mut self, name: ArgName, size: usize) -> Result<()> {
        let start = self.reader.position();
        let value = expression::text(self.reader.read_bytes(size)?, start as u64)?;
        self.field(name, start, Value::Text(value));
        Ok(())
    }
    fn string(&mut self, name: ArgName) -> Result<()> {
        let start = self.reader.position();
        let value = c_string(&mut self.reader)?;
        self.field(name, start, Value::Text(value));
        Ok(())
    }
    fn bytes(&mut self, name: ArgName, size: usize) -> Result<()> {
        let start = self.reader.position();
        let value = self.reader.read_bytes(size)?.to_vec();
        self.field(name, start, Value::Bytes(value));
        Ok(())
    }
    fn finish(&mut self, script: &mut Script, code: u32, name: Qualifier) {
        script.instructions.push(Instruction {
            id: script.instructions.len() as u64,
            span: Span {
                offset: self.start as u64,
                size: (self.reader.position() - self.start) as u64,
            },
            source_line: None,
            opcode: Opcode {
                namespace: self.namespace.clone(),
                code,
                operation: Operation::Data(DataOperation::Record),
                variant: Some(name),
                native_mnemonic: None,
            },
            args: std::mem::take(&mut self.fields),
            attributes: Vec::new(),
        });
        self.start = self.reader.position();
    }
    fn count(&self, count: usize, minimum: usize) -> Result<()> {
        if count > self.reader.remaining() / minimum {
            return Err(corrupt(
                self.reader.position(),
                "Record count exceeds table",
            ));
        }
        Ok(())
    }
}

pub(super) fn disassemble(data: &[u8], mut script: Script) -> Result<Script> {
    let magic = &data[..4];
    let mut r = Record::new(data, 8)?;
    r.start = 0;
    match magic {
        b"YSCM" => {
            r.unsigned(ArgName::CommandCount, 4)?;
            r.unsigned(ArgName::Reserved, 4)?;
            r.finish(&mut script, 0, Qualifier::CommandTable);
            let (definitions, end) = commands(data)?;
            for (id, definition) in definitions.into_iter().enumerate() {
                script.instructions.push(Instruction {
                    id: script.instructions.len() as u64,
                    span: definition.span,
                    source_line: None,
                    opcode: Opcode {
                        namespace: "yuris.command_definition".into(),
                        code: id as u32,
                        operation: Operation::Data(DataOperation::Record),
                        variant: Some(Qualifier::Command),
                        native_mnemonic: Some(definition.name),
                    },
                    args: definition
                        .arguments
                        .into_iter()
                        .enumerate()
                        .map(|(arg_id, arg)| Arg {
                            name: opcode::argument(id as u32, arg_id as u8, arg_id as u8, false),
                            native_name: Some(arg.name),
                            span: arg.span,
                            value: Value::Unsigned(u64::from(arg.kind)),
                            attributes: vec![
                                attribute("id", arg_id as u64),
                                attribute("rule", arg.rule),
                            ],
                        })
                        .collect(),
                    attributes: Vec::new(),
                });
            }
            r.reader.set_position(end)?;
            r.start = end;
            // The loader consumes 37 errno messages followed by a 256-byte key map.
            for id in 0..37 {
                r.string(ArgName::Message)?;
                r.finish(&mut script, id, Qualifier::SystemError);
            }
            for id in 0..256 {
                r.unsigned(ArgName::VirtualKey, 1)?;
                r.finish(&mut script, id, Qualifier::KeyMapping);
            }
        }
        b"YSER" => {
            let count = r.unsigned(ArgName::ErrorCount, 4)? as usize;
            r.unsigned(ArgName::Reserved, 4)?;
            r.finish(&mut script, 0, Qualifier::ErrorTable);
            r.count(count, 5)?;
            for _ in 0..count {
                let code = r.unsigned(ArgName::Code, 4)? as u32;
                r.string(ArgName::Message)?;
                r.finish(&mut script, code, Qualifier::ErrorMessage);
            }
        }
        b"YSTD" => {
            r.unsigned(ArgName::MaximumVariableId, 4)?;
            r.unsigned(ArgName::ReturnCodeCount, 4)?;
            r.finish(&mut script, 0, Qualifier::ScriptMetadata);
        }
        b"YSTL" => {
            let count = r.unsigned(ArgName::ScriptCount, 4)? as usize;
            r.finish(&mut script, 0, Qualifier::ScriptTable);
            r.count(count, 28)?;
            for _ in 0..count {
                let id = r.unsigned(ArgName::ScriptId, 4)? as u32;
                let size = r.unsigned(ArgName::PathLength, 4)? as usize;
                r.text(ArgName::SourcePath, size)?;
                // The runtime skips the first four words; retain their actual order.
                for name in [
                    ArgName::SourceStamp(0),
                    ArgName::SourceStamp(1),
                    ArgName::SourceField(0),
                    ArgName::SourceField(1),
                    ArgName::RuntimeFlags,
                ] {
                    r.unsigned(name, 4)?;
                }
                r.finish(&mut script, id, Qualifier::ScriptFile);
            }
        }
        b"YSLB" => {
            let count = r.unsigned(ArgName::LabelCount, 4)? as usize;
            r.finish(&mut script, 0, Qualifier::LabelTable);
            for id in 0..256 {
                let first = r.unsigned(ArgName::FirstLabel, 4)?;
                if first > count as u64 {
                    return Err(corrupt(r.start, "Label bucket exceeds label table"));
                }
                r.finish(&mut script, id, Qualifier::HashBucket);
            }
            r.count(count, 13)?;
            for id in 0..count {
                let size = r.unsigned(ArgName::NameLength, 1)? as usize;
                let start = r.reader.position();
                let raw = r.reader.read_bytes(size)?;
                r.field(
                    ArgName::Name,
                    start,
                    Value::Text(expression::text(raw, start as u64)?),
                );
                let hash = r.unsigned(ArgName::NameHash, 4)?;
                if hash != u64::from(nvlens_crypto::hash::murmur2::hash(raw, 0)) {
                    return Err(corrupt(start, "Label name hash mismatch"));
                }
                let start = r.reader.position();
                let target = r.reader.read_u32_le()?;
                r.field(
                    ArgName::Instruction,
                    start,
                    Value::InstructionTarget(u64::from(target)),
                );
                r.unsigned(ArgName::ScriptId, 2)?;
                r.unsigned(ArgName::ConditionalDepth, 1)?;
                r.unsigned(ArgName::LoopDepth, 1)?;
                r.finish(&mut script, id as u32, Qualifier::Label);
            }
        }
        b"YSVR" => {
            let count = r.unsigned(ArgName::VariableCount, 2)? as usize;
            r.finish(&mut script, 0, Qualifier::VariableTable);
            r.count(count, 8)?;
            for _ in 0..count {
                r.unsigned(ArgName::Scope, 1)?;
                r.unsigned(ArgName::Storage, 1)?;
                r.unsigned(ArgName::ScriptId, 2)?;
                let id = r.unsigned(ArgName::VariableId, 2)? as u32;
                let ty = r.unsigned(ArgName::Type, 1)?;
                let dimensions = r.unsigned(ArgName::Dimensions, 1)? as usize;
                r.count(dimensions, 4)?;
                for i in 0..dimensions {
                    r.unsigned(ArgName::Dimension(i as u64), 4)?;
                }
                let start = r.reader.position();
                match ty {
                    1 => {
                        let value = r.reader.read_i64_le()?;
                        r.field(ArgName::InitialValue, start, Value::Integer(value));
                    }
                    2 => {
                        let bits = r.reader.read_u64_le()?;
                        r.field(ArgName::InitialValue, start, Value::Float64Bits(bits));
                    }
                    3 => {
                        let size = r.unsigned(ArgName::InitialLength, 2)? as usize;
                        let start = r.reader.position();
                        let tokens = expression::decode(r.reader.read_bytes(size)?, start as u64)?;
                        r.field(ArgName::InitialValue, start, Value::Expression(tokens));
                    }
                    _ => {} // The loader consumes no initializer for other type tags.
                }
                r.finish(&mut script, id, Qualifier::Variable);
            }
        }
        b"YSCF" => {
            r.unsigned(ArgName::ReservedAt(0), 4)?;
            r.unsigned(ArgName::ReservedAt(1), 4)?;
            r.finish(&mut script, 0, Qualifier::ConfigurationTable);
            r.unsigned(ArgName::Width, 4)?;
            r.unsigned(ArgName::Height, 4)?;
            r.unsigned(ArgName::WindowOption, 4)?;
            r.bytes(ArgName::ResourcePriority(0), 8)?;
            r.bytes(ArgName::ResourcePriority(1), 4)?;
            for i in 0..8 {
                r.unsigned(ArgName::Option(i as u64), 4)?;
            }
            r.unsigned(ArgName::ReservedAt(2), 4)?;
            let size = r.unsigned(ArgName::TitleLength, 2)? as usize;
            r.text(ArgName::Title, size)?;
            r.finish(&mut script, 0, Qualifier::Configuration);
        }
        _ => return Err(Error::InvalidFormat),
    }
    if r.reader.remaining() != 0 {
        return Err(corrupt(r.reader.position(), "Unclaimed YBN table bytes"));
    }
    // Source bytes keep ignored fields and original encodings recoverable from IR.
    script.sections.push(section("table", data, 0..data.len()));
    Ok(script)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;

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
    fn labels_include_hash_buckets_and_cross_script_targets() {
        let mut bytes = header(b"YSLB");
        number(&mut bytes, 1, 4);
        for _ in 0..256 {
            number(&mut bytes, 0, 4);
        }
        bytes.push(5);
        bytes.extend_from_slice(b"hello");
        number(&mut bytes, 0xe561_29cb, 4);
        number(&mut bytes, 42, 4);
        number(&mut bytes, 7, 2);
        bytes.extend_from_slice(&[2, 3]);
        complete(&bytes);
        let ir = parse(&bytes);
        assert_eq!(ir.instructions.len(), 258);
        assert!(
            ir.instructions
                .last()
                .unwrap()
                .args
                .iter()
                .any(|p| p.name == ArgName::Instruction
                    && matches!(p.value, Value::InstructionTarget(42)))
        );
        let length = bytes.len();
        bytes[length - 12] ^= 1;
        assert!(super::super::ybn::disassemble(&bytes, None).is_err());
    }

    #[test]
    fn script_list_starts_records_at_twelve_and_preserves_unused_fields() {
        let mut bytes = header(b"YSTL");
        number(&mut bytes, 1, 4);
        number(&mut bytes, 7, 4);
        number(&mut bytes, 8, 4);
        bytes.extend_from_slice(b"main.yst");
        for value in 1..=5 {
            number(&mut bytes, value, 4);
        }
        complete(&bytes);
        let ir = parse(&bytes);
        assert_eq!(ir.instructions[1].span.offset, 12);
        assert_eq!(ir.instructions[1].args.len(), 8);
        assert_eq!(script_paths(&bytes).unwrap(), [(7, "main.yst".into())]);
        for end in 0..bytes.len() {
            assert!(script_paths(&bytes[..end]).is_err());
        }
        bytes[0] = b'X';
        assert!(script_paths(&bytes).is_err());
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

    #[test]
    fn configuration_metadata_and_errors_are_structured() {
        let mut config = header(b"YSCF");
        config.resize(76, 0);
        number(&mut config, 4, 2);
        config.extend_from_slice(b"Game");
        complete(&config);
        assert!(
            parse(&config).instructions[1]
                .args
                .iter()
                .any(|p| p.name == ArgName::Title
                    && matches!(&p.value,Value::Text(s) if s == "Game"))
        );
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
}
