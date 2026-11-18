//! ASB serialized commands, CArtemisParser::load/sub_1400C9A00 (Rev.3257).
//! The five-byte header is "ASB", an uninterpreted byte, and serialization
//! version zero. LE u32 record count follows. Records store type:u32 and a
//! length-prefixed, NUL-terminated UTF-8 name; type 0 adds source_line:u32,
//! argument_count:u32 and name/value string pairs. Type 1 declares a label.
//! Other types carry just their name and are ignored by this native reader.
//! Raw bytes retain unknown header fields, duplicate arguments and trailing data.
use crate::{
    ScriptFormat, ScriptRegistration,
    ir::{
        self, Arg, ArgName, Attribute, DataOperation, Instruction, Opcode, Operation,
        RuntimeOperation, Script, Section, Span, Value,
    },
};
use std::sync::atomic::{AtomicBool, Ordering};
use vnlens_core::{ArchiveOptions, Error, Format, ResourceResolver, Result};
use vnlens_io::{BinaryIo, BinaryReader};

#[derive(Debug, Default)]
struct Asb;
impl Format for Asb {
    fn tag(&self) -> &'static str {
        "asb/artemis"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["asb"]
    }
    fn description(&self) -> &'static str {
        "Artemis ASB serialized command blocks"
    }
}
impl ScriptFormat for Asb {
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        read(data, &AtomicBool::new(false)).map(Some)
    }
    fn disassemble_cancellable(
        &self,
        data: &[u8],
        _: Option<&dyn ResourceResolver>,
        _: &ArchiveOptions,
        cancel: &AtomicBool,
    ) -> Result<Option<Script>> {
        read(data, cancel).map(Some)
    }
}
vnlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Asb)) }

fn string(r: &mut BinaryReader<'_>) -> Result<String> {
    let offset = r.position() as u64;
    let size = usize::try_from(r.read_u32_le()?)
        .map_err(|_| bad(offset, "ASB string exceeds address space"))?;
    let text = r.read_bytes(size)?;
    if r.read_u8()? != 0 {
        return Err(bad(
            r.position() as u64 - 1,
            "ASB string terminator is absent",
        ));
    }
    std::str::from_utf8(text)
        .map(str::to_owned)
        .map_err(|_| bad(offset, "ASB string is not UTF-8"))
}

fn read(data: &[u8], cancel: &AtomicBool) -> Result<Script> {
    check(cancel)?;
    let mut r = BinaryReader::new(data);
    if r.read_bytes(3)? != b"ASB" {
        return Err(Error::InvalidFormat);
    }
    r.read_u8()?;
    let version = r.read_u8()?;
    if version != 0 {
        return Err(Error::Unsupported(format!(
            "Artemis ASB serialization version {version}"
        )));
    }
    let count = r.read_u32_le()?;
    if u64::from(count) > r.remaining() as u64 / 9 {
        return Err(BinaryIo::unexpected_eof("ASB record count exceeds its source").into());
    }
    let mut instructions = Vec::new();
    let mut command_index = 0;
    for id in 0..count {
        check(cancel)?;
        let start = r.position();
        let kind = r.read_u32_le()?;
        let name = string(&mut r)?;
        let mut source_line = None;
        let mut args = Vec::new();
        if kind == 0 {
            source_line = Some(r.read_u32_le()?);
            let argc = r.read_u32_le()?;
            if u64::from(argc) > r.remaining() as u64 / 10 {
                return Err(
                    BinaryIo::unexpected_eof("ASB argument count exceeds its record data").into(),
                );
            }
            for index in 0..argc {
                check(cancel)?;
                let at = r.position();
                let key = string(&mut r)?;
                let value = string(&mut r)?;
                args.push(Arg {
                    name: ArgName::NamedArgument(u64::from(index)),
                    native_name: Some(key),
                    span: Span {
                        offset: at as u64,
                        size: (r.position() - at) as u64,
                    },
                    value: Value::Text(value),
                    attributes: Vec::new(),
                });
            }
        } else {
            args.push(Arg {
                name: if kind == 1 {
                    ArgName::Label
                } else {
                    ArgName::Value
                },
                native_name: None,
                span: Span {
                    offset: start as u64 + 4,
                    size: (r.position() - start - 4) as u64,
                },
                value: Value::Text(name.clone()),
                attributes: Vec::new(),
            });
        }
        instructions.push(Instruction {
            id: u64::from(id),
            span: Span {
                offset: start as u64,
                size: (r.position() - start) as u64,
            },
            source_line,
            opcode: Opcode {
                operation: match kind {
                    0 => Operation::Runtime(RuntimeOperation::EngineCall),
                    1 => Operation::Data(DataOperation::Record),
                    _ => Operation::Unknown,
                },
                variant: None,
                namespace: "artemis.asb".into(),
                code: kind,
                native_mnemonic: (kind == 0).then_some(name),
            },
            args,
            // Native label targets index commands, excluding labels and ignored
            // records. Keep that numbering separately from the IR record ID.
            attributes: if kind <= 1 {
                vec![Attribute {
                    name: "command_index".into(),
                    value: command_index,
                }]
            } else {
                Vec::new()
            },
        });
        if kind == 0 {
            command_index += 1;
        }
    }
    check(cancel)?;
    Ok(Script {
        ir_version: ir::VERSION,
        format: "asb/artemis".into(),
        format_version: u32::from(version),
        sections: vec![Section {
            name: "file".into(),
            span: Span {
                offset: 0,
                size: data.len() as u64,
            },
            raw: data.to_vec(),
        }],
        instructions,
    })
}

fn check(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    Ok(())
}
fn bad(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "../../tests/artemis/asb.rs"]
mod tests;
