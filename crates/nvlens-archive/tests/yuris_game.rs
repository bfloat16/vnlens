//! Local licensed-game validation. Set NVLENS_YURIS_GAME to the game directory:
//! cargo test -p nvlens-archive --test yuris_game -- --ignored --nocapture
//! No game resources or executable bytes are included in the repository.
#![forbid(unsafe_code)]

use nvlens_core::{Archive, Catalog, ResourceResolver, Result};
use nvlens_io::BinaryReader;
use nvlens_script::ir::StorageOperation;
use nvlens_script::ir::{Arg, ArgName, Instruction, Operation, Script, Token, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

struct Resources<'a>(&'a dyn Archive);
impl ResourceResolver for Resources<'_> {
    fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let name = name.replace('\\', "/");
        self.0
            .entries()
            .iter()
            .find(|e| e.name.replace('\\', "/").eq_ignore_ascii_case(&name))
            .map(|entry| self.0.open_entry(entry).map(|bytes| bytes.into_owned()))
            .transpose()
    }
}

#[test]
#[ignore = "Requires a locally owned YU-RIS 0x1EE game and NVLENS_YURIS_GAME"]
fn validates_game_indices_and_every_script() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    nvlens_archive::init();
    let root = PathBuf::from(std::env::var_os("NVLENS_YURIS_GAME").ok_or("Set NVLENS_YURIS_GAME")?);
    let catalog = Catalog::load();
    let game = nvlens_engine::identify(&root, &std::sync::atomic::AtomicBool::new(false))?
        .ok_or("Engine not identified")?;
    for name in ["Graphics.ypf", "Sounds.ypf", "Scripts.ypf"] {
        let opened = catalog.open(
            root.join("pac").join(name),
            &game.route(name).ok_or("No archive route")?,
        )?;
        let entries = opened.archive.entries();
        println!("{name}: {} indexed entries", entries.len());
        if name == "Scripts.ypf" {
            let resources = Resources(&*opened.archive);
            let commands = command_names(
                &resources
                    .read_resource("ysbin/ysc.ybn")?
                    .ok_or("Missing command definitions")?,
            )?;
            let mut instructions = 0;
            let mut scripts = BTreeMap::new();
            let mut references = Vec::new();
            let mut tables = BTreeMap::new();
            let mut args = 0;
            let mut tokens = 0;
            let mut variable_references = Vec::new();
            let mut variable_limit = None;
            let mut decoded = Vec::new();
            let mut dialogue = Vec::new();
            let mut sorted = entries.iter().collect::<Vec<_>>();
            sorted.sort_by_key(|entry| entry.name.to_lowercase());
            for entry in sorted {
                let bytes = opened.archive.open_entry(entry)?;
                let ir = nvlens_script::disassemble_as(
                    game.script_format().ok_or("Missing YU-RIS script route")?,
                    &bytes,
                    Some(&resources),
                )
                .map_err(|e| format!("{}: {e}", entry.name))?
                .ok_or("Script was not recognized")?;
                instructions += ir.instructions.len();
                check_sections(&ir, &bytes);
                if bytes.starts_with(b"YSTB") {
                    scripts.insert(
                        entry.name.replace('\\', "/").to_lowercase(),
                        ir.instructions.len(),
                    );
                    decoded.extend_from_slice(&bytes);
                    let (params, expression_tokens) =
                        check_bytecode(&ir, &bytes, &commands, &mut dialogue);
                    args += params;
                    tokens += expression_tokens;
                    for instruction in &ir.instructions {
                        for operand in &instruction.args {
                            if let Value::Expression(tokens) = &operand.value {
                                for token in tokens {
                                    if matches!(token.opcode.code, 72 | 86 | 118) {
                                        variable_references
                                            .push(unsigned(&token.args, ArgName::VariableId)?);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    let magic = std::str::from_utf8(&bytes[..4])?.to_owned();
                    tables.insert(magic, ir.instructions.len());
                    if bytes.starts_with(b"YSTD") {
                        variable_limit = Some(unsigned(
                            &ir.instructions[0].args,
                            ArgName::MaximumVariableId,
                        )?);
                    }
                    if bytes.starts_with(b"YSVR") {
                        for variable in ir.instructions.iter().skip(1) {
                            variable_references
                                .push(unsigned(&variable.args, ArgName::VariableId)?);
                        }
                    }
                }
                for instruction in &ir.instructions {
                    assert!(
                        instruction.opcode.operation != Operation::Unknown,
                        "{}: unknown opcode",
                        entry.name
                    );
                    assert_eq!(ir.ir_version, nvlens_script::ir::VERSION);
                    for field in &instruction.args {
                        if let Value::ResourceInstructionTarget {
                            resource,
                            instruction,
                            ..
                        } = &field.value
                        {
                            references.push((resource.to_lowercase(), *instruction));
                        }
                    }
                    if bytes.starts_with(b"YSLB")
                        && instruction
                            .opcode
                            .variant
                            .map(nvlens_script::ir::Qualifier::name)
                            == Some("label")
                    {
                        let script = unsigned(&instruction.args, ArgName::ScriptId)?;
                        let target = instruction
                            .args
                            .iter()
                            .find_map(|field| match field.value {
                                Value::InstructionTarget(target) => Some(target),
                                _ => None,
                            })
                            .ok_or("Label target missing")?;
                        references.push((format!("ysbin/yst{script:05}.ybn"), target));
                    }
                }
            }
            for (resource, target) in &references {
                let count = scripts
                    .get(resource)
                    .ok_or_else(|| format!("Missing target script {resource}"))?;
                assert!(
                    *target <= *count as u64,
                    "{resource}: invalid instruction {target}"
                );
            }
            if let Some(maximum) = variable_limit {
                assert!(
                    variable_references.iter().all(|&id| id <= maximum),
                    "Variable reference exceeds declared variable table"
                );
            }
            let digest =
                nvlens_crypto::hash::md5::digest(&std::fs::read(root.join("pac/Scripts.ypf"))?);
            // Golden values independently counted from the licensed 0x1EE sample.
            if hex(&digest) == "946436d78465939589bc36d5dd77b0f3" {
                assert_eq!(scripts.len(), 220);
                assert_eq!(scripts.values().sum::<usize>(), 151_212);
                assert_eq!(args, 538_467);
                assert_eq!(tokens, 670_399);
                assert_eq!(
                    hex(&nvlens_crypto::hash::md5::digest(&decoded)),
                    "fc95ec7b54fc2ff089d999f1597d7888"
                );
                assert_eq!(
                    hex(&nvlens_crypto::hash::md5::digest(&dialogue)),
                    "05f8114dcada4e015a4777d33005823b"
                );
                for (magic, count) in [
                    ("YSCM", 413),
                    ("YSCF", 2),
                    ("YSER", 122),
                    ("YSLB", 2559),
                    ("YSTD", 1),
                    ("YSTL", 227),
                    ("YSVR", 2705),
                ] {
                    assert_eq!(tables.get(magic), Some(&count), "{magic}");
                }
            }
            println!(
                "Disassembled {} files, {instructions} IR records; {args} args, {tokens} expression tokens, {} verified cross-script references",
                entries.len(),
                references.len()
            );
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unsigned(fields: &[Arg], name: ArgName) -> std::result::Result<u64, &'static str> {
    fields
        .iter()
        .find_map(|field| match field.value {
            Value::Unsigned(value) if field.name == name => Some(value),
            _ => None,
        })
        .ok_or("Unsigned field missing")
}

fn check_sections(script: &Script, bytes: &[u8]) {
    let mut offset = 0;
    for section in &script.sections {
        assert_eq!(section.span.offset, offset as u64);
        assert_eq!(section.raw.len() as u64, section.span.size);
        assert_eq!(section.raw, bytes[offset..offset + section.raw.len()]);
        offset += section.raw.len();
    }
    assert_eq!(offset, bytes.len());
}

fn check_bytecode(
    script: &Script,
    bytes: &[u8],
    commands: &[String],
    dialogue: &mut Vec<u8>,
) -> (usize, usize) {
    let count = BinaryReader::u32_le(&bytes[8..]) as usize;
    let code_size = BinaryReader::u32_le(&bytes[12..]) as usize;
    let operand_size = BinaryReader::u32_le(&bytes[16..]) as usize;
    let data_size = BinaryReader::u32_le(&bytes[20..]) as usize;
    let data_start = 32 + code_size + operand_size;
    let lines = data_start + data_size;
    let mut descriptor = 32 + code_size;
    let mut tokens = 0;
    let mut covered = vec![false; data_size];
    assert_eq!(script.instructions.len(), count);
    for (id, instruction) in script.instructions.iter().enumerate() {
        assert_eq!(instruction.id, id as u64);
        assert_eq!(instruction.span.offset, (32 + id * 4) as u64);
        assert_eq!(instruction.opcode.code, u32::from(bytes[32 + id * 4]));
        assert_eq!(
            instruction.opcode.native_mnemonic.as_ref(),
            commands.get(instruction.opcode.code as usize)
        );
        if instruction.opcode.code == 54 {
            let operation = [
                "assign",
                "add_assign",
                "subtract_assign",
                "multiply_assign",
                "divide_assign",
                "remainder_assign",
                "bit_and_assign",
                "bit_or_assign",
                "bit_xor_assign",
            ];
            assert_eq!(
                instruction.opcode.operation,
                Operation::Storage(StorageOperation::Store)
            );
            assert_eq!(
                instruction
                    .opcode
                    .variant
                    .map(nvlens_script::ir::Qualifier::name),
                Some(operation[usize::from(bytes[descriptor + 3])])
            );
        }
        assert_eq!(
            instruction.source_line,
            Some(BinaryReader::u32_le(&bytes[lines + id * 4..]))
        );
        let original = instruction
            .args
            .iter()
            .filter(|p| !p.attributes.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(original.len(), usize::from(bytes[33 + id * 4]));
        for operand in original {
            assert_eq!(operand.span.offset, descriptor as u64);
            descriptor += 12;
            if matches!(operand.value, Value::Group(_)) {
                continue;
            }
            let at = operand.span.offset as usize;
            let length = BinaryReader::u32_le(&bytes[at + 4..]) as usize;
            let relative = BinaryReader::u32_le(&bytes[at + 8..]) as usize;
            let start = data_start + relative;
            covered[relative..relative + length].fill(true);
            assert!(
                matches!(operand.value, Value::Text(_) | Value::Expression(_)),
                "Unparsed operand in {}",
                instruction.disassembly()
            );
            match &operand.value {
                Value::Text(text) => {
                    let raw = &bytes[start..start + length];
                    let expected = encoding_rs::SHIFT_JIS.decode_without_bom_handling(raw).0;
                    assert_eq!(text, &expected);
                    dialogue.extend_from_slice(raw);
                }
                Value::Expression(expression) => {
                    tokens += expression.len();
                    let mut token_offset = start;
                    for token in expression {
                        assert_eq!(token.span.offset, token_offset as u64);
                        assert_eq!(token.opcode.code, u32::from(bytes[token_offset]));
                        assert_eq!(
                            token.raw.len(),
                            usize::from(BinaryReader::u16_le(&bytes[token_offset + 1..]))
                        );
                        assert_eq!(
                            token.raw,
                            bytes[token_offset + 3..token_offset + 3 + token.raw.len()]
                        );
                        assert_ne!(
                            token.opcode.operation,
                            Operation::Unknown,
                            "Unknown expression token"
                        );
                        assert!(
                            !matches!(
                                token.args.first().map(|arg| &arg.value),
                                Some(Value::Bytes(_))
                            ),
                            "Unparsed expression payload"
                        );
                        check_token_value(token);
                        token_offset += token.span.size as usize;
                    }
                    assert_eq!(token_offset, start + length);
                }
                _ => {}
            }
        }
        check_control_targets(instruction, bytes, count);
    }
    assert_eq!(descriptor, data_start);
    assert!(
        covered.iter().all(|covered| *covered),
        "Unreferenced script data"
    );
    (operand_size / 12, tokens)
}

// Read the command-name sequence independently of the disassembler's table model.
fn command_names(bytes: &[u8]) -> std::result::Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut reader = BinaryReader::new(bytes);
    assert_eq!(reader.read_bytes(4)?, b"YSCM");
    assert_eq!(reader.read_u32_le()?, 0x1ee);
    let count = reader.read_u32_le()?;
    reader.read_u32_le()?;
    let mut result = Vec::new();
    for _ in 0..count {
        let mut name = Vec::new();
        loop {
            let byte = reader.read_u8()?;
            if byte == 0 {
                break;
            }
            name.push(byte);
        }
        result.push(
            encoding_rs::SHIFT_JIS
                .decode_without_bom_handling(&name)
                .0
                .into_owned(),
        );
        for _ in 0..reader.read_u8()? {
            while reader.read_u8()? != 0 {}
            reader.read_bytes(2)?;
        }
    }
    Ok(result)
}

fn check_token_value(token: &Token) {
    let raw = &token.raw;
    let name = match token.opcode.code as u8 {
        b'B' | b'W' | b'I' | b'L' => {
            let expected = BinaryReader::compact_i64_le(raw);
            assert!(
                matches!(expected, Ok(value) if matches!(token.args.first().map(|arg| &arg.value), Some(Value::Integer(actual)) if *actual == value))
            );
            assert_eq!(
                token.opcode.variant.map(nvlens_script::ir::Qualifier::name),
                Some("integer")
            );
            "push"
        }
        b'F' => {
            assert!(
                matches!(token.args.first().map(|arg| &arg.value), Some(Value::Float64Bits(bits)) if *bits == BinaryReader::u64_le(raw))
            );
            "push"
        }
        b'H' | b'V' | b'v' => {
            assert_eq!(token.args.len(), 2);
            {
                let fields = &token.args;
                assert!(
                    matches!(&fields[0].value, Value::Text(sigil) if sigil == &char::from(raw[0]).to_string())
                );
                assert_eq!(
                    unsigned(fields, ArgName::VariableId).ok(),
                    Some(u64::from(BinaryReader::u16_le(&raw[1..])))
                );
            }
            match token.opcode.code as u8 {
                b'H' => "load",
                b'V' => "index_begin",
                _ => "reference",
            }
        }
        b')' => {
            assert!(
                matches!(token.args.first().map(|arg| &arg.value), Some(Value::Unsigned(value)) if *value == u64::from(raw[0]))
            );
            "index_end"
        }
        b'M' => "push",
        b'+' => "add",
        b'-' => "subtract",
        b'*' => "multiply",
        b'/' => "divide",
        b'%' => "remainder",
        b'R' => "negate",
        b'=' => "equal",
        b'!' => "not_equal",
        b'<' => "less",
        b'>' => "greater",
        b'S' => "less_equal",
        b'Z' => "greater_equal",
        b'&' => "logical_and",
        b'|' => "logical_or",
        b'A' => "bit_and",
        b'O' => "bit_or",
        b'^' => "bit_xor",
        b's' => "convert",
        b'i' => "convert",
        b',' => "index_separator",
        _ => "unknown",
    };
    assert_eq!(token.opcode.operation.name(), name);
}

fn check_control_targets(instruction: &Instruction, bytes: &[u8], count: usize) {
    for operand in &instruction.args {
        if let Value::Group(fields) = &operand.value {
            for field in fields {
                if let Value::InstructionTarget(target) = field.value {
                    assert!(target <= count as u64);
                    if target != 0 && target < count as u64 {
                        let opcode = bytes[32 + target as usize * 4];
                        assert!(
                            matches!(opcode, 11 | 46 | 49 | 59),
                            "Unexpected control target opcode {opcode}"
                        );
                    }
                }
            }
        }
    }
}
