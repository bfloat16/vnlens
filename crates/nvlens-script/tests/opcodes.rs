//! Public IR contracts across engines, using synthetic bytecode only.
use nvlens_core::{ResourceResolver, Result};
use nvlens_io::BinaryWriter;
use nvlens_script::ir::ArgName;
use nvlens_script::ir::{
    BasicOperation, ControlFlowOperation, DataOperation, RuntimeOperation, StorageOperation,
};
use nvlens_script::{
    disassemble_as,
    ir::{Operation, Script, VERSION, Value},
};

fn word(bytes: &mut Vec<u8>, value: u32) {
    let start = bytes.len();
    bytes.resize(start + 4, 0);
    BinaryWriter::u32_le(value, &mut bytes[start..]);
}

fn compact(body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 16];
    BinaryWriter::u32_le(16, &mut bytes);
    BinaryWriter::u32_le(body.len() as u32, &mut bytes[4..]);
    bytes.extend(body);
    bytes
}

fn compiled(words: &[u32]) -> Vec<u8> {
    let mut bytes = b"BurikoCompiledScriptVer1.00\0".to_vec();
    word(&mut bytes, 4);
    for &value in words {
        word(&mut bytes, value);
    }
    bytes
}

fn yuris(code: u8, argument: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = b"YSTB".to_vec();
    for field in [0x1ee, 1, 4, 12, value.len() as u32, 4, 0] {
        word(&mut bytes, field);
    }
    bytes.extend([code, 1, 0, 0]);
    bytes.extend([argument, 0, 1, 0]);
    word(&mut bytes, value.len() as u32);
    word(&mut bytes, 0);
    bytes.extend(value);
    word(&mut bytes, 1);
    bytes
}

fn parse(tag: &str, bytes: &[u8], resources: Option<&dyn ResourceResolver>) -> Result<Script> {
    nvlens_script::init();
    let script = disassemble_as(tag, bytes, resources)?.ok_or(nvlens_core::Error::InvalidFormat)?;
    assert_eq!(script.ir_version, VERSION);
    assert_eq!(
        script
            .sections
            .iter()
            .flat_map(|s| s.raw.iter().copied())
            .collect::<Vec<_>>(),
        bytes
    );
    Ok(script)
}

#[test]
fn constants_and_arithmetic_share_operations_across_three_instruction_sets() -> Result<()> {
    let compact = parse(
        "script/bgi",
        &compact(&[0x00, 0xff, 0x20, 0x25, 0x17]),
        None,
    )?;
    let compiled = parse(
        "script/bgi",
        &compiled(&[0, u32::MAX, 0x20, 0x25, 0xf4]),
        None,
    )?;
    let expression = [b'B', 1, 0, 0xff, b'+', 0, 0, b'A', 0, 0];
    let yuris = parse("ybn/yuris", &yuris(54, 0, &expression), None)?;
    let Value::Expression(tokens) = &yuris.instructions[0].args[0].value else {
        return Err(nvlens_core::Error::InvalidFormat);
    };
    for (index, operation) in [
        Operation::Storage(StorageOperation::Push),
        Operation::Basic(BasicOperation::Add),
        Operation::Basic(BasicOperation::BitAnd),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(compact.instructions[index].opcode.operation, operation);
        assert_eq!(compiled.instructions[index].opcode.operation, operation);
        assert_eq!(tokens[index].opcode.operation, operation);
    }
    for script in [&compact, &compiled] {
        assert_eq!(
            script.instructions[0]
                .opcode
                .variant
                .map(nvlens_script::ir::Qualifier::name),
            Some("integer")
        );
        assert_eq!(script.instructions[0].args[0].name, ArgName::Value);
        assert!(matches!(
            script.instructions[0].args[0].value,
            Value::Integer(-1)
        ));
    }
    assert_eq!(
        tokens[0]
            .opcode
            .variant
            .map(nvlens_script::ir::Qualifier::name),
        Some("integer")
    );
    assert!(matches!(
        tokens[0].args.first().map(|arg| &arg.value),
        Some(Value::Integer(-1))
    ));
    assert_eq!(
        yuris.instructions[0].opcode.operation,
        Operation::Storage(StorageOperation::Store)
    );
    assert_eq!(
        yuris.instructions[0]
            .opcode
            .variant
            .map(nvlens_script::ir::Qualifier::name),
        Some("assign")
    );
    Ok(())
}

#[test]
fn common_operations_keep_store_shift_and_unknown_semantics_distinct() -> Result<()> {
    let compact = parse(
        "script/bgi",
        &compact(&[0x0c, 2, 1, 0x2a, 0x2b, 0x7f, 0xfe, 0x17]),
        None,
    )?;
    let compiled = parse(
        "script/bgi",
        &compiled(&[0x0a, 0, 0x2a, 0x2b, 0xabcd, 0xf4]),
        None,
    )?;
    assert_eq!(
        compact.instructions[0].opcode.operation,
        Operation::Storage(StorageOperation::Store)
    );
    assert_eq!(
        compiled.instructions[0].opcode.operation,
        Operation::Storage(StorageOperation::Store)
    );
    assert_eq!(
        compact.instructions[0]
            .opcode
            .variant
            .map(nvlens_script::ir::Qualifier::name),
        Some("many")
    );
    assert_eq!(
        compiled.instructions[0]
            .opcode
            .variant
            .map(nvlens_script::ir::Qualifier::name),
        Some("unchecked")
    );
    for script in [&compact, &compiled] {
        for (index, variant) in [(1, "logical"), (2, "arithmetic")] {
            assert_eq!(
                script.instructions[index].opcode.operation,
                Operation::Basic(BasicOperation::ShiftRight)
            );
            assert_eq!(
                script.instructions[index]
                    .opcode
                    .variant
                    .map(nvlens_script::ir::Qualifier::name),
                Some(variant)
            );
        }
        let unknown = &script.instructions[3];
        assert_eq!(unknown.opcode.operation, Operation::Unknown);
        assert_eq!(unknown.opcode_name(), "unknown");
        assert!(
            unknown
                .args_disassembly()
                .contains(&unknown.opcode.namespace)
        );
    }
    assert_eq!(compact.instructions[3].opcode.code, 0x7ffe);
    assert_eq!(compiled.instructions[3].opcode.code, 0xabcd);
    let exported = serde_json::from_slice::<serde_json::Value>(&compiled.to_json()?)
        .map_err(|e| nvlens_core::Error::Unsupported(e.to_string()))?;
    assert_eq!(
        exported["instructions"][1]["opcode"]["operation"],
        "shift_right"
    );
    assert!(
        exported["instructions"][1]["opcode"]
            .get("mnemonic")
            .is_none()
    );
    Ok(())
}

#[test]
fn engine_calls_and_command_records_keep_native_names_and_empty_parameters() -> Result<()> {
    struct Commands(Vec<u8>);
    impl ResourceResolver for Commands {
        fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
            Ok((name == "ysbin/ysc.ybn").then(|| self.0.clone()))
        }
    }
    let mut table = b"YSCM".to_vec();
    for value in [0x1ee, 1, 0] {
        word(&mut table, value);
    }
    table.extend(b"CUSTOM\0\x02TEXT\0\x01\0\0\0\0");
    table.extend([0; 37 + 256]);
    let resources = Commands(table.clone());
    for (id, expected, native) in [
        (0, ArgName::Unknown(0), "TEXT"),
        (1, ArgName::Unknown(1), ""),
    ] {
        let script = parse(
            "ybn/yuris",
            &yuris(0, id, &[b'B', 1, 0, 1]),
            Some(&resources),
        )?;
        let instruction = &script.instructions[0];
        assert_eq!(
            instruction.opcode.operation,
            Operation::Runtime(RuntimeOperation::EngineCall)
        );
        assert_eq!(
            instruction.opcode.native_mnemonic.as_deref(),
            Some("CUSTOM")
        );
        assert_eq!(instruction.args[0].name, expected);
        assert_eq!(instruction.args[0].native_name.as_deref(), Some(native));
    }
    let table = parse("ybn/yuris", &table, None)?;
    assert_eq!(
        table.instructions[1].opcode.operation,
        Operation::Data(DataOperation::Record)
    );
    assert_eq!(
        table.instructions[1].opcode.namespace,
        "yuris.command_definition"
    );
    assert_eq!(
        table.instructions[1].opcode.native_mnemonic.as_deref(),
        Some("CUSTOM")
    );
    assert_eq!(
        table.instructions[1].args[1].native_name.as_deref(),
        Some("")
    );
    Ok(())
}

#[test]
fn code_and_data_addresses_remain_distinct_under_shared_push() -> Result<()> {
    let script = parse(
        "script/bgi",
        &compact(&[0x05, 7, 0, 0x06, 3, 0, 0x17, b'x', 0]),
        None,
    )?;
    for instruction in &script.instructions[..2] {
        assert_eq!(
            instruction.opcode.operation,
            Operation::Storage(StorageOperation::Push)
        );
    }
    assert!(matches!(
        script.instructions[0].args[0].value,
        Value::DataAddress(23)
    ));
    assert!(matches!(
        script.instructions[1].args[0].value,
        Value::CodeAddress(22)
    ));
    assert_eq!(script.instructions[0].args[0].name, ArgName::DataOffset);
    assert_eq!(script.instructions[1].args[0].name, ArgName::Target);
    let compiled = parse("script/bgi", &compiled(&[1, 8, 0x1b]), None)?;
    assert!(matches!(
        compiled.instructions[0].args[0].value,
        Value::CodeAddress(40)
    ));
    assert_eq!(
        compiled.instructions[0]
            .opcode
            .variant
            .map(nvlens_script::ir::Qualifier::name),
        Some("code_address")
    );
    Ok(())
}

fn lua53(code: &[u32]) -> Vec<u8> {
    let mut bytes = b"\x1bLua\x53\0\x19\x93\r\n\x1a\n\x04\x08\x04\x08\x08".to_vec();
    for n in [0x5678, 370.5f64.to_bits()] {
        let mut b = [0; 8];
        BinaryWriter::u64_le(n, &mut b);
        bytes.extend(b);
    }
    bytes.extend([0, 0]); // Main upvalues and inherited source.
    word(&mut bytes, 0);
    word(&mut bytes, 0);
    bytes.extend([0, 0, 3]);
    word(&mut bytes, code.len() as u32);
    for &n in code {
        word(&mut bytes, n);
    }
    word(&mut bytes, 1);
    bytes.push(19); // Integer constant.
    let mut b = [0; 8];
    BinaryWriter::u64_le(42, &mut b);
    bytes.extend(b);
    for _ in 0..5 {
        word(&mut bytes, 0);
    }
    bytes
}

#[test]
fn lua_uses_native_opcodes_and_fields_without_shared_semantic_mapping() -> Result<()> {
    let words = [
        1 | (1 << 6),              // LOADK R1 K0.
        13 | (2 << 6) | (1 << 23), // ADD R2 R1 R0.
        18 | (2 << 6) | (1 << 23), // DIV.
        19 | (2 << 6) | (1 << 23), // IDIV.
        24 | (2 << 6) | (1 << 23), // SHR.
        31 | (1 << 23),            // EQ.
        30 | ((131071 + 1) << 14), // JMP to PC 8.
        0,                         // MOVE.
        37 | (2 << 6) | (1 << 23), // TAILCALL.
        38 | (1 << 23),            // RETURN.
        63,                        // Unknown native opcode, retains its word and ID.
    ];
    let script = parse("lua", &lua53(&words), None)?;
    let code = &script.instructions[1..];
    assert_eq!(code.len(), words.len());
    for instruction in code {
        assert_eq!(instruction.opcode.operation, Operation::Native);
        assert!(instruction.opcode.variant.is_none());
    }
    for (instruction, name) in code.iter().zip([
        "LOADK", "ADD", "DIV", "IDIV", "SHR", "EQ", "JMP", "MOVE", "TAILCALL", "RETURN", "OP_3F",
    ]) {
        assert_eq!(instruction.opcode_name(), name);
    }
    assert_eq!(
        code[0].args[0].name,
        ArgName::Native(nvlens_script::ir::NativeArg::A)
    );
    assert_eq!(
        code[0].args[1].name,
        ArgName::Native(nvlens_script::ir::NativeArg::Bx)
    );
    let Value::Group(constant) = &code[0].args[1].value else {
        return Err(nvlens_core::Error::InvalidFormat);
    };
    assert_eq!(constant[0].name, ArgName::ConstantIndex);
    assert!(matches!(constant[1].value, Value::Integer(42)));
    assert_eq!(constant[1].span.size, 0);
    assert_eq!(
        code[6].args[1].name,
        ArgName::Native(nvlens_script::ir::NativeArg::SBx)
    );
    assert!(matches!(code[6].args[1].value, Value::Integer(1)));
    assert!(code[6].args.iter().any(|o| o.name == ArgName::Target
        && o.span.size == 0
        && matches!(o.value, Value::CodeAddress(a) if a == code[8].span.offset)));
    assert_eq!(code[10].opcode.code, 63);
    assert_eq!(code[10].args[0].name, ArgName::Word);
    let aux = parse("lua", &lua53(&[2, 46, 38 | (1 << 23)]), None)?;
    assert_eq!(aux.instructions[2].opcode.operation, Operation::Native);
    assert_eq!(aux.instructions[2].opcode_name(), "EXTRAARG");
    assert!(
        aux.instructions[2]
            .attributes
            .iter()
            .any(|a| a.name == "owner_pc" && a.value == 0)
    );
    let json: serde_json::Value = serde_json::from_slice(&script.to_json()?)
        .map_err(|e| nvlens_core::Error::Unsupported(e.to_string()))?;
    assert_eq!(json["instructions"][2]["opcode"]["operation"], "native");
    assert_eq!(json["instructions"][2]["opcode"]["native_mnemonic"], "ADD");
    Ok(())
}

#[test]
fn advhd_and_exhibit_keep_typed_targets_unknowns_and_native_identity() -> Result<()> {
    use nvlens_core::{ArchiveOptions, Secret};
    let mut schema = Vec::new();
    for code in 0..256 {
        match code {
            2 => schema.extend([4, 255]),
            3 => schema.extend([4, 255]),
            _ => schema.push(254),
        }
    }
    let mut options = ArchiveOptions::default();
    options.keys.insert("will_ws2", Secret::new(schema));
    let mut ws2 = vec![2];
    word(&mut ws2, 10);
    ws2.push(3);
    word(&mut ws2, 123);
    ws2.push(255);
    ws2.extend([0; 8]);
    nvlens_script::init();
    let adv = nvlens_script::disassemble_with_options_as("ws2/will", &ws2, None, &options)?
        .ok_or(nvlens_core::Error::InvalidFormat)?;
    assert_eq!(
        adv.instructions[0].opcode.operation,
        Operation::ControlFlow(ControlFlowOperation::Jump)
    );
    assert_eq!(adv.instructions[0].args[0].name, ArgName::Target);
    assert!(matches!(
        adv.instructions[0].args[0].value,
        Value::CodeAddress(10)
    ));
    // A valid parameter table only proves boundaries, not command semantics.
    assert_eq!(adv.instructions[1].opcode.operation, Operation::Unknown);
    assert_eq!(adv.instructions[1].args[0].name, ArgName::Unknown(0));
    assert!(matches!(
        adv.instructions[1].args[0].value,
        Value::Unsigned(123)
    ));
    let mut rld = Vec::new();
    for n in [
        0x524c4400, 0, 16, 4, 0x10005, 7, 0x10014, 9, 0x1002f, 9, 0x1ffff, 123,
    ] {
        word(&mut rld, n);
    }
    let exhibit = parse("rld/exhibit", &rld, None)?;
    assert_eq!(
        exhibit.instructions[0].opcode.operation,
        Operation::Runtime(RuntimeOperation::EngineCall)
    );
    assert_eq!(
        exhibit.instructions[0].opcode.native_mnemonic.as_deref(),
        Some("block")
    );
    assert_eq!(exhibit.instructions[1].args[0].name, ArgName::LabelId);
    assert!(matches!(
        exhibit.instructions[1].args[0].value,
        Value::Integer(9)
    ));
    assert!(matches!(
        exhibit.instructions[1].args[1].value,
        Value::InstructionTarget(2)
    ));
    assert_eq!(exhibit.instructions[1].args[1].span.size, 0);
    assert_eq!(
        exhibit.instructions[2]
            .opcode
            .variant
            .map(nvlens_script::ir::Qualifier::name),
        Some("label")
    );
    assert_eq!(exhibit.instructions[3].opcode.operation, Operation::Unknown);
    assert_eq!(exhibit.instructions[3].args[0].name, ArgName::Unknown(0));
    Ok(())
}

#[test]
fn different_engines_map_audio_commands_to_the_same_ir_operations() -> Result<()> {
    use nvlens_core::{ArchiveOptions, Secret};
    use nvlens_script::ir::{AudioOperation, Category};
    let mut schema = Vec::new();
    for code in 0..256 {
        schema.push(if matches!(code, 40..=42) { 255 } else { 254 });
    }
    let mut options = ArchiveOptions::default();
    options.keys.insert("will_ws2", Secret::new(schema));
    let mut ws2 = vec![40, 41, 42];
    ws2.extend([0; 8]);
    nvlens_script::init();
    let adv = nvlens_script::disassemble_with_options_as("ws2/will", &ws2, None, &options)?
        .ok_or(nvlens_core::Error::InvalidFormat)?;
    let mut rld = Vec::new();
    for n in [0x524c4400, 0, 16, 3, 50, 51, 59] {
        word(&mut rld, n);
    }
    let exhibit = parse("rld/exhibit", &rld, None)?;
    for (index, operation) in [
        AudioOperation::Play,
        AudioOperation::Stop,
        AudioOperation::SetVolume,
    ]
    .into_iter()
    .enumerate()
    {
        let a = &adv.instructions[index];
        let b = &exhibit.instructions[index];
        assert_eq!(a.opcode.operation, Operation::Audio(operation));
        assert_eq!(a.opcode.operation, b.opcode.operation);
        assert_eq!(a.opcode.operation.category(), Category::Audio);
        assert_eq!(a.opcode_name(), b.opcode_name());
        assert_ne!(a.opcode.code, b.opcode.code);
        assert_ne!(a.opcode.namespace, b.opcode.namespace);
        assert_eq!(a.span.size, 1);
        assert_eq!(b.span.size, 4);
    }
    let json: serde_json::Value = serde_json::from_slice(&adv.to_json()?)
        .map_err(|e| nvlens_core::Error::Unsupported(e.to_string()))?;
    assert_eq!(json["ir_version"], 5);
    assert_eq!(json["instructions"][0]["opcode"]["category"], "audio");
    assert_eq!(json["instructions"][0]["opcode"]["operation"], "play_audio");
    assert_eq!(
        exhibit.instructions[0].opcode.native_mnemonic.as_deref(),
        Some("cmdPlayMusic")
    );
    assert_eq!(
        exhibit.instructions[0]
            .opcode
            .variant
            .map(nvlens_script::ir::Qualifier::name),
        Some("music")
    );
    Ok(())
}

#[test]
fn presentation_commands_have_distinct_semantics_and_keep_native_fields() -> Result<()> {
    use nvlens_script::ir::{EffectOperation, ImageOperation, TextOperation, VideoOperation};
    let cases = [
        (28, Operation::Text(TextOperation::Show), "show_text"),
        (30, Operation::Text(TextOperation::Clear), "clear_text"),
        (74, Operation::Image(ImageOperation::Draw), "draw_image"),
        (87, Operation::Effect(EffectOperation::Blur), "blur"),
        (
            88,
            Operation::Effect(EffectOperation::StopBlur),
            "stop_blur",
        ),
        (105, Operation::Effect(EffectOperation::Fade), "fade"),
        (
            106,
            Operation::Effect(EffectOperation::StopFade),
            "stop_fade",
        ),
        (136, Operation::Effect(EffectOperation::Shake), "shake"),
        (112, Operation::Video(VideoOperation::Play), "play_video"),
        (114, Operation::Video(VideoOperation::Stop), "stop_video"),
        (0xffff, Operation::Unknown, "unknown"),
    ];
    let mut bytes = Vec::new();
    for n in [0x524c4400, 0, 16, cases.len() as u32] {
        word(&mut bytes, n);
    }
    for &(code, _, _) in &cases {
        word(&mut bytes, code | 0x10000);
        word(&mut bytes, 123);
    }
    let script = parse("rld/exhibit", &bytes, None)?;
    for (instruction, &(code, operation, name)) in script.instructions.iter().zip(&cases) {
        assert_eq!(instruction.opcode.operation, operation);
        assert_eq!(instruction.opcode_name(), name);
        assert_eq!(instruction.opcode.code, code);
        assert_eq!(instruction.args[0].name, ArgName::Unknown(0));
        assert!(matches!(instruction.args[0].value, Value::Integer(123)));
    }
    Ok(())
}

#[test]
fn volume_arguments_share_names_and_shape_across_engines() -> Result<()> {
    use nvlens_core::{ArchiveOptions, Secret};
    let mut schema = vec![254; 42];
    schema.extend([6, 8, 5, 1, 255]); // Channel string, terminator, duration, volume.
    schema.extend([254; 213]);
    let mut options = ArchiveOptions::default();
    options.keys.insert("will_ws2", Secret::new(schema));
    let mut ws2 = vec![42];
    for unit in "bgm".encode_utf16().chain([0]) {
        let mut encoded = [0; 2];
        BinaryWriter::u16_le(unit, &mut encoded);
        ws2.extend(encoded);
    }
    word(&mut ws2, 0.5f32.to_bits());
    let mut volume = [0; 2];
    BinaryWriter::u16_le(50, &mut volume);
    ws2.extend(volume);
    ws2.extend([0; 8]);
    nvlens_script::init();
    let adv = nvlens_script::disassemble_with_options_as("ws2/will", &ws2, None, &options)?
        .ok_or(nvlens_core::Error::InvalidFormat)?;
    let mut rld = Vec::new();
    for n in [0x524c4400, 0, 16, 1, 0x4003b, 0, 2, 50, 500] {
        word(&mut rld, n);
    }
    let exhibit = parse("rld/exhibit", &rld, None)?;
    assert_eq!(
        adv.instructions[0].opcode.operation,
        exhibit.instructions[0].opcode.operation
    );
    for name in [ArgName::Channel, ArgName::Duration, ArgName::Volume] {
        for script in [&adv, &exhibit] {
            assert_eq!(
                script.instructions[0]
                    .args
                    .iter()
                    .filter(|arg| arg.name == name)
                    .count(),
                1
            );
        }
    }
    // Preserve native units and types; a common role is not permission to
    // silently change a duration, channel selector or signed volume value.
    assert!(
        matches!(adv.instructions[0].args[2].value, Value::Float32Bits(v) if v == 0.5f32.to_bits())
    );
    assert!(matches!(
        exhibit.instructions[0].args[3].value,
        Value::Integer(500)
    ));
    let json: serde_json::Value = serde_json::from_slice(&adv.to_json()?)
        .map_err(|e| nvlens_core::Error::Unsupported(e.to_string()))?;
    let instruction = &json["instructions"][0];
    assert!(instruction.get("operands").is_none());
    assert_eq!(instruction["args"][0]["category"], "audio");
    assert_eq!(instruction["args"][0]["name"], "channel");
    assert_eq!(instruction["args"][1]["name"], "terminator");
    assert_eq!(instruction["args"][1]["index"], 1);
    Ok(())
}

#[test]
fn expression_arguments_use_the_instruction_argument_contract() -> Result<()> {
    let script = parse("ybn/yuris", &yuris(54, 0, &[b'B', 1, 0, 7]), None)?;
    let json: serde_json::Value = serde_json::from_slice(&script.to_json()?)
        .map_err(|e| nvlens_core::Error::Unsupported(e.to_string()))?;
    let argument = &json["instructions"][0]["args"][0];
    assert_eq!(argument["name"], "destination");
    let token = &argument["value"]["value"][0];
    assert!(token.get("value").is_none());
    let token_arg = &token["args"][0];
    assert_eq!(token_arg["name"], "value");
    assert_eq!(token_arg["category"], "basic");
    assert_eq!(token_arg["value"]["kind"], "integer");
    assert_eq!(token_arg["value"]["value"], 7);
    for key in ["span", "attributes"] {
        assert!(argument.get(key).is_some());
        assert!(token_arg.get(key).is_some());
    }
    Ok(())
}

#[test]
fn unknown_opcodes_and_all_argument_slots_survive_without_shifting_the_next_instruction()
-> Result<()> {
    use nvlens_core::{ArchiveOptions, Secret};
    let mut schema = vec![254; 3];
    schema.extend([4, 6, 8, 7, 4, 255]);
    schema.extend([254; 252]);
    let mut options = ArchiveOptions::default();
    options.keys.insert("will_ws2", Secret::new(schema));
    let mut ws2 = vec![3];
    word(&mut ws2, 123);
    ws2.extend([0, 0]); // A valid empty string, retained as its own argument.
    ws2.push(2);
    word(&mut ws2, 456);
    word(&mut ws2, 789);
    let next = ws2.len();
    ws2.push(255);
    ws2.extend([0; 8]);
    nvlens_script::init();
    let adv = nvlens_script::disassemble_with_options_as("ws2/will", &ws2, None, &options)?
        .ok_or(nvlens_core::Error::InvalidFormat)?;
    assert_eq!(adv.instructions.len(), 2);
    assert_eq!(adv.instructions[0].opcode.operation, Operation::Unknown);
    assert_eq!(adv.instructions[0].args.len(), 4);
    assert_eq!(adv.instructions[0].args[0].name, ArgName::Unknown(0));
    assert_eq!(adv.instructions[0].args[1].name, ArgName::Unknown(1));
    assert!(matches!(&adv.instructions[0].args[1].value, Value::Text(s) if s.is_empty()));
    assert_eq!(adv.instructions[0].args[2].name, ArgName::Terminator(2));
    assert_eq!(adv.instructions[0].args[3].name, ArgName::Unknown(3));
    let Value::Group(repeated) = &adv.instructions[0].args[3].value else {
        return Err(nvlens_core::Error::InvalidFormat);
    };
    assert_eq!(repeated.len(), 3);
    assert_eq!(repeated[0].name, ArgName::Count);
    assert!(matches!(repeated[1].value, Value::Unsigned(456)));
    assert!(matches!(repeated[2].value, Value::Unsigned(789)));
    assert_eq!(adv.instructions[1].span.offset, next as u64);
    assert_eq!(
        adv.instructions[1].opcode.operation,
        Operation::ControlFlow(ControlFlowOperation::Halt)
    );
    let mut rld = Vec::new();
    for n in [0x524c4400, 0, 16, 2, 0x0a15ffff] {
        word(&mut rld, n);
    }
    for n in 0..21 {
        word(&mut rld, n);
    }
    rld.extend([0; 10]); // Every empty string still occupies a slot.
    let next = rld.len();
    word(&mut rld, 24);
    let exhibit = parse("rld/exhibit", &rld, None)?;
    let unknown = &exhibit.instructions[0];
    assert_eq!(unknown.opcode.operation, Operation::Unknown);
    assert_eq!(unknown.args.len(), 31);
    for (index, arg) in unknown.args.iter().enumerate() {
        assert_eq!(arg.name, ArgName::Unknown(index as u64));
        assert!(arg.span.size > 0);
    }
    assert_eq!(exhibit.instructions[1].span.offset, next as u64);
    Ok(())
}

#[test]
fn systemnnn_exports_shared_store_and_audio_semantics_with_lossless_native_identity() -> Result<()>
{
    use nvlens_script::ir::{AudioOperation, Qualifier};
    let mut bytes = vec![0; 76];
    BinaryWriter::u32_le(19, &mut bytes);
    BinaryWriter::u32_le(0x66660001, &mut bytes[4..]);
    BinaryWriter::u32_le(0x55550001, &mut bytes[8..]);
    bytes[48..58].copy_from_slice(b"SPTHEADER0");
    for value in [
        8, 0x66660005, 0, 0xa0000000, 3, 0x80000007, 0x90000002, 0xa200002b, 6, 0x66660007,
        0x33330068, 2, 1, 0xfffffffb, 5, 0x6666ffff, 0xabcdef, 11, 22,
    ] {
        word(&mut bytes, value);
    }
    let script = parse("spt/systemnnn", &bytes, None)?;
    assert_eq!(
        script.instructions[1].opcode.operation,
        Operation::Storage(StorageOperation::Store)
    );
    assert_eq!(
        script.instructions[1].opcode.variant,
        Some(Qualifier::AddAssign)
    );
    assert_eq!(
        script.instructions[2].opcode.operation,
        Operation::Audio(AudioOperation::SetVolume)
    );
    assert_eq!(script.instructions[2].args[1].name, ArgName::Channel);
    assert_eq!(script.instructions[2].args[2].name, ArgName::Volume);
    assert!(matches!(
        script.instructions[2].args[2].value,
        Value::Integer(-5)
    ));
    assert_eq!(script.instructions[3].opcode.operation, Operation::Unknown);
    assert_eq!(script.instructions[3].args[1].name, ArgName::Unknown(1));
    let exported: serde_json::Value = serde_json::from_slice(&script.to_json()?)
        .map_err(|error| nvlens_core::Error::Unsupported(error.to_string()))?;
    let store = &exported["instructions"][1];
    assert_eq!(store["opcode"]["category"], "storage");
    assert_eq!(store["opcode"]["operation"], "store");
    assert_eq!(store["opcode"]["variant"], "add_assign");
    assert_eq!(store["opcode"]["namespace"], "systemnnn/66660005");
    let token = &store["args"][0]["value"]["value"][0];
    assert_eq!(token["opcode"]["operation"], "reference");
    assert_eq!(token["args"][0]["name"], "variable_id");
    assert!(token.get("value").is_none());
    assert_eq!(exported["instructions"][2]["args"][2]["category"], "audio");
    Ok(())
}
