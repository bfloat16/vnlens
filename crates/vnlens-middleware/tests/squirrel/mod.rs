use super::*;
use vnlens_io::BinaryWriter;
fn word(out: &mut Vec<u8>, value: u32) {
    let mut bytes = [0; 4];
    BinaryWriter::u32_le(value, &mut bytes);
    out.extend(bytes);
}
fn string(out: &mut Vec<u8>, value: &str) {
    word(out, 0x0800_0010);
    word(out, value.len() as u32);
    out.extend(value.as_bytes());
}
fn fixture(depth: usize) -> Vec<u8> {
    let mut bytes = vec![0xfa, 0xfa];
    word(&mut bytes, 0x5351_4952);
    word(&mut bytes, 1);
    for level in 0..=depth {
        word(&mut bytes, PART);
        string(&mut bytes, "fixture.nut");
        string(&mut bytes, "main");
        word(&mut bytes, PART);
        for count in [1, 0, 0, 0, 1, 0, 3, u32::from(level < depth)] {
            word(&mut bytes, count);
        }
        word(&mut bytes, PART);
        string(&mut bytes, "message");
        for _ in 0..4 {
            word(&mut bytes, PART);
        }
        word(&mut bytes, 7);
        word(&mut bytes, 0);
        word(&mut bytes, PART);
        word(&mut bytes, PART);
        for op in [1, 0x18, 0x13] {
            word(&mut bytes, 0);
            bytes.extend([op, 0, 0, 0]);
        }
        word(&mut bytes, PART);
    }
    for _ in 0..=depth {
        word(&mut bytes, 1);
        bytes.extend([0, 0]);
    }
    word(&mut bytes, 0x5441_494c);
    bytes
}
#[test]
fn native_operands_literals_branches_and_nested_prototypes() -> Result<()> {
    for depth in [0, 1, 128] {
        let bytes = fixture(depth);
        let script = disassemble(&bytes)?;
        assert_eq!(script.format, "Squirrel");
        assert_eq!(script.instructions.len(), (depth + 1) * 3);
        assert_eq!(
            script.instructions[0].opcode.native_mnemonic.as_deref(),
            Some("LOAD")
        );
        assert_eq!(script.instructions[0].source_line, Some(7));
        assert_eq!(
            script.instructions[0].opcode.operation,
            ir::Operation::Native
        );
        let names = script.instructions[0].args[..4]
            .iter()
            .map(|a| a.name.name())
            .collect::<Vec<_>>();
        assert_eq!(names, ["arg0", "arg1", "arg2", "arg3"]);
        let json: serde_json::Value = serde_json::from_str(&script.instructions[0].to_json()?)
            .map_err(|e| Error::Unsupported(e.to_string()))?;
        assert_eq!(json["args"][0]["name"], "arg0");
        assert_eq!(json["args"][0]["category"], "native");
        assert!(
            script.instructions[0]
                .args
                .iter()
                .any(|a| matches!(&a.value,Value::Text(text) if text=="message"))
        );
        assert!(script.instructions[1].args.iter().any(
            |a| matches!(a.value,Value::CodeAddress(at) if at==script.instructions[2].span.offset)
        ));
        assert_eq!(script.sections[0].raw, bytes);
    }
    Ok(())
}
#[test]
fn truncated_and_unknown_instructions_are_lossless() -> Result<()> {
    let mut bytes = fixture(0);
    for end in 0..bytes.len() {
        assert!(disassemble(&bytes[..end]).is_err(), "end={end}");
    }
    let script = disassemble(&bytes)?;
    let at = script.instructions[0].span.offset as usize;
    bytes[at + 4] = 255;
    let unknown = disassemble(&bytes)?;
    assert_eq!(
        unknown.instructions[0].opcode.operation,
        ir::Operation::Unknown
    );
    bytes[at + 4] = 1;
    BinaryWriter::u32_le(1, &mut bytes[at..]);
    assert!(disassemble(&bytes).is_err());
    Ok(())
}
