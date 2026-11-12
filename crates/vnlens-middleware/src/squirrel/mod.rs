//! Squirrel 2.2.4 SQClosure/SQFunctionProto::Load, verified against
//! sub_14024DFA0, sub_14024E1D0 and sub_14024F280. LE 32-bit integers/floats,
//! one-byte characters and eight-byte instructions, even in the 64-bit host.
//! Opcode names/layout follow Squirrel's sqopcodes.h; see THIRD_PARTY_NOTICES.
use vnlens_core::ir::{
    self, Arg, ArgName, Attribute, Instruction, NativeArg, Opcode, Script, Section, Span, Value,
};
use vnlens_core::{Error, Result};
use vnlens_io::BinaryReader;
mod opcode;
const PART: u32 = 0x5041_5254;
fn bad(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}
fn tag(reader: &mut BinaryReader<'_>, expected: u32) -> Result<()> {
    let at = reader.position();
    if reader.read_u32_le()? != expected {
        return Err(bad(at, "Invalid Squirrel serialization tag"));
    }
    Ok(())
}
fn object(reader: &mut BinaryReader<'_>) -> Result<Value> {
    let at = reader.position();
    Ok(match reader.read_u32_le()? {
        0x0100_0001 => Value::Nil,
        0x0500_0002 => Value::Integer(i64::from(reader.read_u32_le()? as i32)),
        0x0500_0004 => Value::Float32Bits(reader.read_u32_le()?),
        0x0800_0010 => {
            let length = reader.read_u32_le()? as usize;
            let bytes = reader.read_bytes(length)?;
            match std::str::from_utf8(bytes) {
                Ok(text) => Value::Text(text.into()),
                Err(_) => Value::Bytes(bytes.into()),
            }
        }
        _ => return Err(bad(at, "Unsupported Squirrel serialized object type")),
    })
}
fn argument(name: ArgName, at: usize, size: usize, value: Value) -> Arg {
    Arg {
        name,
        native_name: None,
        span: Span {
            offset: at as u64,
            size: size as u64,
        },
        value,
        attributes: Vec::new(),
    }
}
struct Pending {
    children: u32,
    start: usize,
    instruction_start: usize,
    instruction_end: usize,
}

/// Disassembles a Squirrel 2.2.4 serialized closure into owned native records.
/// Malformed tags, truncated tables and invalid references return an error.
pub fn disassemble(data: &[u8]) -> Result<Script> {
    let mut reader = BinaryReader::new(data);
    if reader.read_u16_le()? != 0xfafa {
        return Err(Error::InvalidFormat);
    }
    tag(&mut reader, 0x5351_4952)?;
    tag(&mut reader, 1)?;
    let mut script = Script {
        ir_version: ir::VERSION,
        format: "Squirrel".into(),
        format_version: 0x020204,
        sections: vec![Section {
            name: "serialized_closure".into(),
            span: Span {
                offset: 0,
                size: data.len() as u64,
            },
            raw: data.to_vec(),
        }],
        instructions: Vec::new(),
    };
    let mut pending = vec![function(&mut reader, &mut script)?];
    while let Some(frame) = pending.last_mut() {
        if frame.children != 0 {
            frame.children -= 1;
            pending.push(function(&mut reader, &mut script)?);
        } else {
            let stack = reader.read_u32_le()?;
            let generator = reader.read_u8()?;
            let varargs = reader.read_u8()?;
            if generator > 1 || varargs > 1 {
                return Err(bad(
                    reader.position() - 2,
                    "Invalid Squirrel function flags",
                ));
            }
            for instruction in
                &mut script.instructions[frame.instruction_start..frame.instruction_end]
            {
                instruction.attributes.extend([
                    Attribute {
                        name: "function_offset".into(),
                        value: frame.start as u64,
                    },
                    Attribute {
                        name: "stack_size".into(),
                        value: u64::from(stack),
                    },
                    Attribute {
                        name: "generator".into(),
                        value: u64::from(generator),
                    },
                    Attribute {
                        name: "varargs".into(),
                        value: u64::from(varargs),
                    },
                ]);
            }
            pending.pop();
        }
    }
    tag(&mut reader, 0x5441_494c)?;
    if reader.remaining() != 0 {
        return Err(bad(reader.position(), "Trailing Squirrel closure data"));
    }
    Ok(script)
}

fn function(reader: &mut BinaryReader<'_>, script: &mut Script) -> Result<Pending> {
    let start = reader.position();
    tag(reader, PART)?;
    let source = object(reader)?;
    let name = object(reader)?;
    tag(reader, PART)?;
    let mut counts = [0u32; 8];
    for value in &mut counts {
        *value = reader.read_u32_le()?;
    }
    let [
        literals,
        parameters,
        outers,
        locals,
        lines,
        defaults,
        instructions,
        children,
    ] = counts;
    let minimum = u64::from(literals) * 4
        + u64::from(parameters) * 4
        + u64::from(outers) * 12
        + u64::from(locals) * 16
        + u64::from(lines) * 8
        + u64::from(defaults) * 4
        + u64::from(instructions) * 8;
    if minimum > reader.remaining() as u64 || counts.iter().any(|&n| n > i32::MAX as u32) {
        return Err(bad(
            start,
            "Squirrel tables exceed serialized function data",
        ));
    }
    tag(reader, PART)?;
    let mut constants = Vec::new();
    for _ in 0..literals {
        constants.push(object(reader)?);
    }
    tag(reader, PART)?;
    for _ in 0..parameters {
        object(reader)?;
    }
    tag(reader, PART)?;
    for _ in 0..outers {
        reader.read_u32_le()?;
        object(reader)?;
        object(reader)?;
    }
    tag(reader, PART)?;
    for _ in 0..locals {
        object(reader)?;
        reader.read_bytes(12)?;
    }
    tag(reader, PART)?;
    let mut locations = Vec::new();
    for _ in 0..lines {
        locations.push((reader.read_u32_le()?, reader.read_u32_le()?));
    }
    if locations.windows(2).any(|pair| pair[0].1 > pair[1].1) {
        return Err(bad(start, "Unordered Squirrel line table"));
    }
    tag(reader, PART)?;
    reader.read_bytes(defaults as usize * 4)?;
    tag(reader, PART)?;
    let code_start = reader.position();
    let instruction_start = script.instructions.len();
    for index in 0..instructions {
        let at = reader.position();
        let a1 = reader.read_u32_le()?;
        let op = reader.read_u8()?;
        let a0 = reader.read_u8()?;
        let a2 = reader.read_u8()?;
        let a3 = reader.read_u8()?;
        let mut args = vec![
            argument(
                ArgName::Native(NativeArg::Named("arg0")),
                at + 5,
                1,
                Value::Unsigned(u64::from(a0)),
            ),
            argument(
                ArgName::Native(NativeArg::Named("arg1")),
                at,
                4,
                Value::Integer(i64::from(a1 as i32)),
            ),
            argument(
                ArgName::Native(NativeArg::Named("arg2")),
                at + 6,
                1,
                Value::Unsigned(u64::from(a2)),
            ),
            argument(
                ArgName::Native(NativeArg::Named("arg3")),
                at + 7,
                1,
                Value::Unsigned(u64::from(a3)),
            ),
        ];
        if matches!(op, 1 | 4 | 8 | 9) {
            let value = constants
                .get(a1 as usize)
                .ok_or_else(|| bad(at, "Squirrel literal index exceeds its pool"))?;
            args.push(argument(ArgName::InitialValue, at, 4, value.clone()));
        }
        if op == 4 {
            let value = constants
                .get(usize::from(a3))
                .ok_or_else(|| bad(at + 7, "Squirrel second literal exceeds its pool"))?;
            args.push(argument(ArgName::InitialValue, at + 7, 1, value.clone()));
        }
        if matches!(op, 0x18..=0x1a | 0x2b | 0x2c | 0x33 | 0x34 | 0x38) {
            let target = i64::from(index) + 1 + i64::from(a1 as i32);
            if target < 0 || target > i64::from(instructions) {
                return Err(bad(at, "Squirrel branch leaves its function"));
            }
            args.push(argument(
                ArgName::Target,
                at,
                4,
                Value::CodeAddress(code_start as u64 + target as u64 * 8),
            ));
        }
        args.push(argument(ArgName::SourceFile, start, 0, source.clone()));
        args.push(argument(ArgName::Name, start, 0, name.clone()));
        let line = locations
            .partition_point(|&(_, offset)| offset <= index)
            .checked_sub(1)
            .map(|i| locations[i].0);
        let (operation, mnemonic) = opcode::decode(op);
        script.instructions.push(Instruction {
            id: at as u64,
            span: Span {
                offset: at as u64,
                size: 8,
            },
            source_line: line,
            opcode: Opcode {
                operation,
                variant: None,
                namespace: "squirrel/2.2".into(),
                code: u32::from(op),
                native_mnemonic: mnemonic.map(str::to_owned),
            },
            args,
            attributes: Vec::new(),
        });
    }
    tag(reader, PART)?;
    Ok(Pending {
        children,
        start,
        instruction_start,
        instruction_end: script.instructions.len(),
    })
}

#[cfg(test)]
#[path = "../../tests/squirrel/mod.rs"]
mod tests;
