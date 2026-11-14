//! STCM2 action bytecode. Layout follows ScriptLoader, exportAction,
//! decodeParameters/decodeScalar (sub_127A50/sub_127E30 in the verified host)
//! and stcm2-asm's action framing. All offsets are absolute little-endian u32.
//! An action is four words, N parameter triples, then private object storage.
//! Game opcodes are deliberately left numeric: their handlers vary by game.
mod opcode;

use crate::{ScriptFormat, ScriptRegistration};
use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_core::ir::*;
use vnlens_core::{ArchiveOptions, Error, Format, ResourceResolver, Result};
use vnlens_io::{BinaryIo, BinaryReader};

const SIGNATURES: &[u32] = &[0x4d43_5453];

#[derive(Debug, Default)]
struct Stcm2;
impl Format for Stcm2 {
    fn tag(&self) -> &'static str {
        "stcm2/otomate"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["dat", "stcm2"]
    }
    fn description(&self) -> &'static str {
        "Otomate STCM2 action bytecode"
    }
}
impl ScriptFormat for Stcm2 {
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        parse(data, &AtomicBool::new(false)).map(Some)
    }
    fn disassemble_cancellable(
        &self,
        data: &[u8],
        _: Option<&dyn ResourceResolver>,
        _: &ArchiveOptions,
        cancelled: &AtomicBool,
    ) -> Result<Option<Script>> {
        parse(data, cancelled).map(Some)
    }
}
vnlens_core::inventory::submit! { ScriptRegistration(|| Box::new(Stcm2)) }

fn parse(data: &[u8], cancelled: &AtomicBool) -> Result<Script> {
    check_cancel(cancelled)?;
    let header = bytes(data, 0, 0x50)?;
    if &header[..5] != b"STCM2" {
        return Err(Error::InvalidFormat);
    }
    if header[5] != b'L' {
        return Err(Error::Unsupported("Unsupported STCM2 byte order".into()));
    }
    let export_at = word(data, 0x20)? as usize;
    let export_count = word(data, 0x24)? as usize;
    let version = word(data, 0x28)?;
    if !matches!(version, 1 | 2) {
        return Err(Error::Unsupported(format!(
            "Unsupported STCM2 runtime version {version}"
        )));
    }
    let export_marker = export_at
        .checked_sub(12)
        .ok_or_else(|| bad(0x20, "STCM2 export offset precedes marker"))?;
    if bytes(data, 0x50, 12)? != b"GLOBAL_DATA\0" {
        return Err(bad(0x50, "Missing STCM2 global data marker"));
    }
    if export_marker < 0x5c {
        return Err(bad(0x20, "STCM2 exports overlap header"));
    }
    if bytes(data, export_marker, 12)? != b"EXPORT_DATA\0" {
        return Err(bad(export_marker, "Missing STCM2 export marker"));
    }
    let mut code_marker = None;
    for at in (0x5c..export_marker).step_by(4) {
        check_cancel(cancelled)?;
        if data.get(at..at + 12) == Some(b"CODE_START_\0") {
            code_marker = Some(at);
            break;
        }
    }
    let code_marker = code_marker.ok_or_else(|| bad(0x5c, "Missing STCM2 code marker"))?;
    let export_size = export_count
        .checked_mul(40)
        .ok_or_else(|| bad(0x24, "STCM2 export size overflow"))?;
    bytes(data, export_at, export_size)?;
    let mut instructions = vec![record(
        0,
        0x50,
        vec![
            arg(ArgName::Signature, 0, 5, Value::Bytes(header[..5].to_vec())),
            arg(
                ArgName::Version,
                0x28,
                4,
                Value::Unsigned(u64::from(version)),
            ),
            arg(
                ArgName::Metadata,
                5,
                27,
                Value::Bytes(header[5..0x20].to_vec()),
            ),
            arg(
                ArgName::DataOffset,
                0x20,
                4,
                Value::DataAddress(export_at as u64),
            ),
            arg(
                ArgName::Count,
                0x24,
                4,
                Value::Unsigned(export_count as u64),
            ),
            arg(
                ArgName::Reserved,
                0x2c,
                0x24,
                Value::Bytes(header[0x2c..].to_vec()),
            ),
        ],
    )];
    let mut starts = BTreeSet::new();
    let mut targets = Vec::new();
    let mut at = code_marker + 12;
    while at < export_marker {
        check_cancel(cancelled)?;
        let action = bytes(data, at, 16)?;
        let call = BinaryReader::u32_le(action);
        let code = BinaryReader::u32_le(&action[4..]);
        let count = BinaryReader::u32_le(&action[8..]) as usize;
        let size = BinaryReader::u32_le(&action[12..]) as usize;
        let parameter_size = count
            .checked_mul(12)
            .and_then(|n| n.checked_add(16))
            .ok_or_else(|| bad(at + 8, "STCM2 parameter range overflow"))?;
        if size < parameter_size || size > export_marker - at {
            return Err(bad(
                at + 12,
                "STCM2 action length exceeds code or omits parameters",
            ));
        }
        if call > 1 {
            return Err(bad(at, "Invalid STCM2 global-call flag"));
        }
        starts.insert(at);
        let mut args = Vec::new();
        if call == 1 {
            targets.push((at + 4, code as usize));
            args.push(arg(
                ArgName::Target,
                at + 4,
                4,
                Value::CodeAddress(u64::from(code)),
            ));
        }
        for index in 0..count {
            check_cancel(cancelled)?;
            args.push(parameter(
                data,
                at + 16 + index * 12,
                index,
                if call == 0 { Some(code) } else { None },
                &mut targets,
            )?);
        }
        let object_at = at + parameter_size;
        if size > parameter_size {
            args.push(arg(
                ArgName::Data,
                object_at,
                size - parameter_size,
                Value::Bytes(bytes(data, object_at, size - parameter_size)?.to_vec()),
            ));
        }
        let (operation, mnemonic) = if call == 1 {
            (
                Operation::ControlFlow(ControlFlowOperation::Call),
                Some("global_call".into()),
            )
        } else {
            opcode::describe(code)
        };
        instructions.push(Instruction {
            id: 0,
            span: span(at, size),
            source_line: None,
            opcode: Opcode {
                operation,
                variant: None,
                namespace: "otomate.stcm2".into(),
                code,
                native_mnemonic: mnemonic,
            },
            args,
            attributes: vec![
                Attribute {
                    name: "global_call".into(),
                    value: u64::from(call),
                },
                Attribute {
                    name: "parameter_count".into(),
                    value: count as u64,
                },
            ],
        });
        at += size;
    }
    for (field, target) in targets {
        if !starts.contains(&target) {
            return Err(bad(
                field,
                "STCM2 action reference is not an action boundary",
            ));
        }
    }
    for i in 0..export_count {
        check_cancel(cancelled)?;
        let row = export_at + i * 40;
        let name = bytes(data, row + 4, 32)?;
        let target = word(data, row + 36)? as usize;
        if !starts.contains(&target) {
            return Err(bad(row + 36, "STCM2 export is not an action boundary"));
        }
        instructions.push(record(
            row,
            40,
            vec![
                arg(
                    ArgName::Type,
                    row,
                    4,
                    Value::Unsigned(u64::from(word(data, row)?)),
                ),
                arg(ArgName::Name, row + 4, 32, text_or_bytes(name)),
                arg(
                    ArgName::Target,
                    row + 36,
                    4,
                    Value::CodeAddress(target as u64),
                ),
            ],
        ));
    }
    // Unlike the old assembler's opaque +0x2c collection blob, the runtime
    // accesses the optional collection table through +0x34/+0x38.
    let collection_at = word(data, 0x34)? as usize;
    let collection_count = word(data, 0x38)? as usize;
    if collection_at != 0 && collection_count != 0 {
        bytes(
            data,
            collection_at,
            collection_count
                .checked_mul(0x50)
                .ok_or_else(|| bad(0x38, "STCM2 collection size overflow"))?,
        )?;
        for i in 0..collection_count {
            check_cancel(cancelled)?;
            let row = collection_at + i * 0x50;
            let name_at = word(data, row + 4)? as usize;
            let rest = data
                .get(name_at..)
                .ok_or_else(|| eof("STCM2 collection name exceeds source"))?;
            let length = rest
                .iter()
                .position(|v| *v == 0)
                .ok_or_else(|| eof("Unterminated STCM2 collection name"))?;
            instructions.push(record(
                row,
                0x50,
                vec![
                    arg(
                        ArgName::Data,
                        row,
                        0x50,
                        Value::Bytes(bytes(data, row, 0x50)?.to_vec()),
                    ),
                    arg(
                        ArgName::Name,
                        name_at,
                        length + 1,
                        text_or_bytes(&rest[..length]),
                    ),
                ],
            ));
        }
    }
    for (id, instruction) in instructions.iter_mut().enumerate() {
        instruction.id = id as u64;
    }
    check_cancel(cancelled)?;
    Ok(Script {
        ir_version: VERSION,
        format: "stcm2/otomate".into(),
        format_version: version,
        sections: vec![Section {
            name: "stcm2".into(),
            span: span(0, data.len()),
            raw: data.to_vec(),
        }],
        instructions,
    })
}

fn parameter(
    data: &[u8],
    at: usize,
    index: usize,
    opcode: Option<u32>,
    targets: &mut Vec<(usize, usize)>,
) -> Result<Arg> {
    let raw = bytes(data, at, 12)?;
    let first = BinaryReader::u32_le(raw);
    let second = BinaryReader::u32_le(&raw[4..]);
    let third = BinaryReader::u32_le(&raw[8..]);
    let mut fields = vec![arg(ArgName::Descriptor, at, 12, Value::Bytes(raw.to_vec()))];
    match first >> 30 {
        0 => {
            let object = first as usize;
            let header = bytes(data, object, 16)?;
            let size = BinaryReader::u32_le(&header[12..]) as usize;
            let payload = bytes(data, object + 16, size)?;
            fields.push(arg(
                ArgName::DataOffset,
                at,
                4,
                Value::DataAddress(u64::from(first)),
            ));
            for (name, delta) in [
                (ArgName::ValueType, 0),
                (ArgName::Width, 4),
                (ArgName::Height, 8),
                (ArgName::ByteCount, 12),
            ] {
                fields.push(arg(
                    name,
                    object + delta,
                    4,
                    Value::Unsigned(u64::from(BinaryReader::u32_le(&header[delta..]))),
                ));
            }
            fields.push(arg(
                ArgName::Data,
                object + 16,
                size,
                Value::Bytes(payload.to_vec()),
            ));
            if second == 0x4000_0000
                && third == 0x4000_0000
                && opcode.is_some_and(|code| opcode::string_parameter(code, index))
            {
                fields.push(arg(
                    ArgName::Text,
                    object + 16,
                    size,
                    text_or_bytes(payload),
                ));
            }
            // Dynamic array indices remain encoded; do not resolve registers
            // or treat arbitrary four-byte objects as strings.
            fields.push(arg(
                ArgName::Index,
                at + 4,
                4,
                Value::Unsigned(u64::from(second)),
            ));
            fields.push(arg(
                ArgName::Dimension(1),
                at + 8,
                4,
                Value::Unsigned(u64::from(third)),
            ));
        }
        1 => fields.push(arg(
            ArgName::Value,
            at,
            4,
            Value::Unsigned(u64::from(first & 0x3fff_ffff)),
        )),
        _ if first == 0xffff_ff41 => {
            targets.push((at + 4, second as usize));
            fields.push(arg(
                ArgName::Target,
                at + 4,
                4,
                Value::CodeAddress(u64::from(second)),
            ));
        }
        _ => {}
    }
    Ok(arg(
        ArgName::Unknown(index as u64),
        at,
        12,
        Value::Group(fields),
    ))
}
fn text_or_bytes(data: &[u8]) -> Value {
    let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    std::str::from_utf8(&data[..end])
        .map_or_else(|_| Value::Bytes(data.to_vec()), |s| Value::Text(s.into()))
}
fn record(offset: usize, size: usize, args: Vec<Arg>) -> Instruction {
    Instruction {
        id: 0,
        span: span(offset, size),
        source_line: None,
        opcode: Opcode {
            operation: Operation::Data(DataOperation::Record),
            variant: None,
            namespace: "otomate.stcm2.metadata".into(),
            code: 0,
            native_mnemonic: None,
        },
        args,
        attributes: Vec::new(),
    }
}
fn span(offset: usize, size: usize) -> Span {
    Span {
        offset: offset as u64,
        size: size as u64,
    }
}
fn arg(name: ArgName, offset: usize, size: usize, value: Value) -> Arg {
    Arg {
        name,
        native_name: None,
        span: span(offset, size),
        value,
        attributes: Vec::new(),
    }
}
fn bytes(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| bad(offset, "STCM2 range overflow"))?;
    data.get(offset..end)
        .ok_or_else(|| eof("STCM2 range exceeds source"))
}
fn word(data: &[u8], offset: usize) -> Result<u32> {
    Ok(BinaryReader::u32_le(bytes(data, offset, 4)?))
}
fn eof(reason: &str) -> Error {
    BinaryIo::unexpected_eof(reason).into()
}
fn bad(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
fn check_cancel(cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/otomate/mod.rs"]
mod tests;
