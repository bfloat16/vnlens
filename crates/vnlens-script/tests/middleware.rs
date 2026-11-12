use super::*;
use vnlens_core::ir::Operation;
use vnlens_io::BinaryWriter;

fn lua_fixture() -> Vec<u8> {
    let mut bytes = b"\x1bLua\x54\0\x19\x93\r\n\x1a\n\x04\x08\x08".to_vec();
    let mut value = [0; 8];
    BinaryWriter::u64_le(0x5678, &mut value);
    bytes.extend(value);
    BinaryWriter::u64_le(370.5f64.to_bits(), &mut value);
    bytes.extend(value);
    bytes.extend([0, 0x80, 0x80, 0x80, 0, 0, 2, 0x81]);
    let mut instruction = [0; 4];
    BinaryWriter::u32_le(71 | (1 << 16), &mut instruction);
    bytes.extend(instruction);
    bytes.extend([0x80; 7]);
    bytes
}

#[test]
fn selected_lua_route_uses_middleware_native_disassembly() -> Result<()> {
    let bytes = lua_fixture();
    let script: vnlens_core::ir::Script =
        crate::disassemble_as("lua", &bytes, None)?.ok_or(vnlens_core::Error::InvalidFormat)?;
    assert_eq!(script.instructions[1].opcode.operation, Operation::Native);
    assert_eq!(
        script.instructions[1].opcode.native_mnemonic.as_deref(),
        Some("RETURN0")
    );
    assert_eq!(script.sections[0].raw, bytes);
    assert_eq!(
        crate::decode_text_as("lua", b"return 1")?,
        Some("return 1".into())
    );
    assert!(crate::decode_text_as("lua", &bytes)?.is_none());
    assert!(crate::disassemble_as("lua", b"return 1", None)?.is_none());
    assert!(crate::disassemble_as("lua", b"\x1bLua", None).is_err());
    assert!(crate::disassemble_as("script/kaleido", &[0xfa, 0xfa], None).is_err());
    Ok(())
}
