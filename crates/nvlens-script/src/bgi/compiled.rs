//! BurikoCompiledScriptVer1.00: 28-byte magic, u32 header extent (measured
//! from offset 28), then little-endian u32 opcodes. Address/string immediates
//! are relative to the code base. Control flow and referenced code addresses
//! delimit code; unvisited bytes remain losslessly preserved as program data.
//! Immediate counts also follow scrctrl._bp's installed handlers: its 0x478
//! helper advances the bytecode cursor, while 0x49D/0x591 consume stack values.
use super::opcode;
use super::*;
use crate::ir::ArgName;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
struct Header {
    code_base: usize,
}
impl Header {
    fn parse(data: &[u8]) -> Result<Self> {
        let mut r = BinaryReader::new(data);
        if r.read_bytes(28)? != b"BurikoCompiledScriptVer1.00\0" {
            return Err(Error::InvalidFormat);
        }
        let extent = r.read_u32_le()? as usize;
        if extent < 4 {
            return Err(corrupt(28, "Compiled BGI header overlaps size field"));
        }
        let code_base = 28usize
            .checked_add(extent)
            .ok_or_else(|| corrupt(28, "BGI header offset overflow"))?;
        r.set_position(code_base)?;
        Ok(Self { code_base })
    }
}

pub(super) fn parse(data: &[u8]) -> Result<Script> {
    let header = Header::parse(data)?;
    let base = header.code_base;
    let bytes = &data[base..];
    let mut pending = BTreeSet::from([0usize]);
    let mut instructions: BTreeMap<usize, Instruction> = BTreeMap::new();
    let mut text_start = bytes.len();
    while let Some(mut pc) = pending.pop_first() {
        while pc < text_start && !instructions.contains_key(&pc) {
            if instructions
                .range(..pc)
                .next_back()
                .is_some_and(|(_, i)| i.span.offset + i.span.size > (base + pc) as u64)
            {
                return Err(corrupt(base + pc, "Compiled BGI branch enters operand"));
            }
            let mut r = BinaryReader::new_at(bytes, pc)?;
            let code = r.read_u32_le()?;
            // 0x0A stores one value without 0x09's address checks
            // (scrctrl._bp+0x93E); its immediate is not an item count.
            let ((operation, variant), count) = opcode::compiled(code);
            let mut args = Vec::new();
            for index in 0..count {
                let start = r.position();
                let value = r.read_u32_le()?;
                let mut op = operand(
                    opcode::compiled_arg(code, index),
                    base + start,
                    base + r.position(),
                    Value::Integer(i64::from(value as i32)),
                );
                if code == 1 {
                    let target = value as usize;
                    if target >= bytes.len() || !target.is_multiple_of(4) {
                        return Err(corrupt(base + start, "Invalid compiled BGI code address"));
                    }
                    op.name = ArgName::Target;
                    op.value = Value::CodeAddress((base + target) as u64);
                    pending.insert(target);
                } else if code == 3 || (code == 0x7f && index == 0) {
                    let target = value as usize;
                    text_start = text_start.min(target);
                    op.name = if code == 0x7f {
                        ArgName::SourceFile
                    } else {
                        ArgName::Text
                    };
                    op.value = text_at(bytes, target)?;
                    op.attributes.push(Attribute {
                        name: "string_offset".into(),
                        value: (base + target) as u64,
                    });
                }
                args.push(op);
            }
            let end = r.position();
            if end > text_start || instructions.range(pc..end).next().is_some() {
                return Err(corrupt(base + pc, "Compiled BGI code overlaps data"));
            }
            instructions.insert(
                pc,
                Instruction {
                    id: 0,
                    span: Span {
                        offset: (base + pc) as u64,
                        size: (end - pc) as u64,
                    },
                    source_line: None,
                    opcode: Opcode {
                        namespace: "bgi.compiled".into(),
                        code,
                        operation,
                        variant,
                        native_mnemonic: None,
                    },
                    args,
                    attributes: Vec::new(),
                },
            );
            pc = end;
            if matches!(code, 0x15 | 0x16 | 0x18 | 0x1b | 0xf4) {
                break;
            }
        }
    }
    let mut instructions: Vec<_> = instructions.into_values().collect();
    for (id, instruction) in instructions.iter_mut().enumerate() {
        instruction.id = id as u64;
    }
    Ok(Script {
        ir_version: VERSION,
        format: "script/bgi/compiled".into(),
        format_version: 100,
        sections: vec![
            section("header", 0, &data[..base]),
            section("program", base, bytes),
        ],
        instructions,
    })
}

#[cfg(test)]
#[path = "../../tests/bgi/compiled.rs"]
mod tests;
