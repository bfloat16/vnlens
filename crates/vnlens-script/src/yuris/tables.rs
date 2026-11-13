//! YU-RIS auxiliary tables. The 0x1EE engine loaders are 0x45D83C
//! (YSCM), 0x45DEFC (YSTD), 0x45E15C (YSTL), 0x45E45C (YSCF),
//! 0x45E97C (YSLB), and variable initialization at 0x45293C (YSVR).
//! The same little-endian layouts are used by 0x22B loaders 0x463550,
//! 0x463C08, 0x463CCC, 0x463E2C, 0x464170, and 0x451798 respectively.
//! The earlier 0x1DF readers 0x455090 (YSCM), 0x45599C (YSTL), and
//! 0x4561BC (YSLB) retain these record layouts but use different command IDs.
//! YSCM readers 0x447A34 (0x12C), 0x44CFCC (0x1C6), 0x44E2A4
//! (0x1D0), 0x4544AC (0x1DA), and 0x4549DC (0x1DC) retain the command
//! strings, argument kind/rule bytes, 37 errors, and 256-byte key map.
//! YSVR 0x1DF/0x1E0 readers 0x44AC6C/0x450A98 have seven-byte variable
//! headers; the 0x1E6 reader 0x450DC0 adds a storage byte after the scope.
//! The 0x1E1 reader 0x45253C already includes that storage byte; its YSCM
//! loader uses the same definitions, 37 error strings and 256-byte key map.
//! YSVR 0x226..=0x22A uses seven-byte records without storage; 0x22B
//! adds that field, independently of the YSTL and YSCF transitions below.
//! Other revisions between 0x1E1 and 0x1E6 are not assumed to share either layout.
//! YSLB names use IEEE CRC32 or MurmurHash2 with seed zero (label lookup
//! sub_45126C). All records in a table must agree on the hash algorithm.
//! YSTL 0x226..=0x227 records retain four source metadata words without runtime flags;
//! their complete record coverage differs from the five-word layouts above.
//! Earlier YSTL 0x12C..=0x1DE also has four metadata words (0x4483E0, 0x44D928,
//! 0x454E08, 0x455338); the 0x1DF branch adds runtime flags.
//! YSCF 0x226..=0x228 has six option words and no reserved word before its title length,
//! placing the length at 0x40 rather than 0x4C in the later layout.
//! The earlier 0x12C..=0x1DE configuration uses the same compact framing
//! (0x448534, 0x44DA7C, 0x454F5C, 0x45548C).
//! Table headers differ; record boundaries are not inferred from a shared header.

use super::{attribute, c_string, corrupt, expression, opcode, operand, section};
use crate::ir::DataOperation;
use crate::ir::*;
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{Error, Result};
use vnlens_io::BinaryReader;

#[derive(Debug)]
pub struct Argument {
    pub name: String,
    pub kind: u8,
    pub rule: u8,
    pub span: Span,
}

#[derive(Debug)]
pub struct Command {
    pub name: String,
    pub arguments: Vec<Argument>,
    pub span: Span,
}

/// Reads native definitions and returns the consumed byte offset. Callers
/// retain any remaining table fields rather than silently discarding them.
pub fn commands(data: &[u8], cancelled: Option<&AtomicBool>) -> Result<(Vec<Command>, usize)> {
    let mut r = BinaryReader::new(data);
    if r.read_bytes(4)? != b"YSCM" {
        return Err(corrupt(0, "Companion command table is not YSCM"));
    }
    let version = r.read_u32_le()?;
    if !matches!(version, 0x12c..=0x1e1 | 0x1e6..=0x22b) {
        return Err(Error::Unsupported(format!("YSCM version 0x{version:X}")));
    }
    let count = r.read_u32_le()? as usize;
    r.read_u32_le()?;
    if count > r.remaining() / 2 {
        return Err(corrupt(8, "Command count exceeds table"));
    }
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        if cancelled.is_some_and(|cancel| cancel.load(Ordering::Relaxed)) {
            return Err(Error::Cancelled);
        }
        let start = r.position();
        let name = c_string(&mut r)?;
        let count = usize::from(r.read_u8()?);
        if count > r.remaining() / 3 {
            return Err(corrupt(r.position(), "Argument count exceeds table"));
        }
        let mut arguments = Vec::with_capacity(count);
        for _ in 0..count {
            if cancelled.is_some_and(|cancel| cancel.load(Ordering::Relaxed)) {
                return Err(Error::Cancelled);
            }
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
            let (definitions, end) = commands(data, None)?;
            for (id, definition) in definitions.into_iter().enumerate() {
                let semantic =
                    opcode::semantic_code(script.format_version, id as u32, Some(&definition.name));
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
                            name: opcode::argument(semantic, arg_id as u8, arg_id as u8, false),
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
            let has_runtime_flags = !matches!(script.format_version, 0x12c..=0x1de | 0x226..=0x227);
            r.count(count, if has_runtime_flags { 28 } else { 24 })?;
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
                ] {
                    r.unsigned(name, 4)?;
                }
                if has_runtime_flags {
                    r.unsigned(ArgName::RuntimeFlags, 4)?;
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
            let mut crc32 = true;
            let mut murmur2 = true;
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
                crc32 &= hash == u64::from(vnlens_crypto::checksum::crc32::ieee(0, raw));
                murmur2 &= hash == u64::from(vnlens_crypto::hash::murmur2::hash(raw, 0));
                if !crc32 && !murmur2 {
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
            let has_storage =
                script.format_version >= 0x1e1 && !matches!(script.format_version, 0x226..=0x22a);
            r.count(count, if has_storage { 8 } else { 7 })?;
            for _ in 0..count {
                r.unsigned(ArgName::Scope, 1)?;
                if has_storage {
                    r.unsigned(ArgName::Storage, 1)?;
                }
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
            let compact = matches!(script.format_version, 0x12c..=0x1de | 0x226..=0x228);
            for i in 0..if compact { 6 } else { 8 } {
                r.unsigned(ArgName::Option(i as u64), 4)?;
            }
            if !compact {
                r.unsigned(ArgName::ReservedAt(2), 4)?;
            }
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
#[path = "../../tests/yuris/tables.rs"]
mod tests;
