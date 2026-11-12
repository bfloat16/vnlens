#![allow(clippy::unwrap_used)]

use super::*;
use vnlens_io::BinaryWriter;

fn msb_fixture(glyph_width: usize) -> Vec<u8> {
    let mut bytes = vec![0; 32];
    bytes[..4].copy_from_slice(b"MES\0");
    BinaryWriter::u32_le(1, &mut bytes[4..]);
    BinaryWriter::u32_le(2, &mut bytes[8..]);
    BinaryWriter::u32_le(32, &mut bytes[12..]);
    BinaryWriter::u32_le(10, &mut bytes[16..]);
    BinaryWriter::u32_le(0, &mut bytes[20..]);
    BinaryWriter::u32_le(11, &mut bytes[24..]);
    BinaryWriter::u32_le(u32::MAX, &mut bytes[28..]);
    if glyph_width == 2 {
        bytes.extend_from_slice(&[0x80, 0x2a, 0x00, 0xff]);
    } else {
        bytes.extend_from_slice(&[0x80, 0x00, 0x01, 0x2a, 0x00, 0xff]);
    }
    bytes
}

fn scx_fixture() -> Vec<u8> {
    let code_start = 12 + 4096 * 4;
    let code_end = code_start + 4;
    let returns_start = code_end;
    let mut bytes = vec![0; code_end + 4];
    bytes[..4].copy_from_slice(b"SC3\0");
    BinaryWriter::u32_le(code_end as u32, &mut bytes[4..]);
    BinaryWriter::u32_le(returns_start as u32, &mut bytes[8..]);
    BinaryWriter::u32_le(code_start as u32, &mut bytes[12..]);
    // 0x0000 = Halt
    bytes[code_start] = 0x00;
    bytes[code_start + 1] = 0x00;
    BinaryWriter::u32_le(code_start as u32, &mut bytes[returns_start..]);
    bytes
}

#[test]
fn requires_identified_glyph_width_and_disassembles_msb_and_scx() -> Result<()> {
    let msb2 = msb_fixture(2);
    assert!(matches!(
        Msb.disassemble(&msb2, None),
        Err(Error::Unsupported(_))
    ));
    for (width, expected) in [(2u64, 0x2au64), (4u64, 0x12au64)] {
        let mut options = ArchiveOptions::default();
        options.numbers.insert("mages_glyph_width", width);
        let data = msb_fixture(width as usize);
        let script = Msb
            .disassemble_with_options(&data, None, &options)?
            .ok_or(Error::InvalidFormat)?;
        assert_eq!(script.instructions.len(), 2);
        let Value::Expression(tokens) = &script.instructions[0].args[1].value else {
            return Err(Error::InvalidFormat);
        };
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[0].args[0].value, Value::Unsigned(v) if v == expected));
        assert!(matches!(script.instructions[1].args[1].value, Value::Nil));
    }

    let mut options = ArchiveOptions::default();
    options.numbers.insert("mages_glyph_width", 2);
    let scx = scx_fixture();
    let script = Scx
        .disassemble_with_options(&scx, None, &options)?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(script.instructions.len(), 1);
    assert_eq!(
        script.instructions[0].opcode.operation,
        Operation::ControlFlow(ControlFlowOperation::Halt)
    );
    Ok(())
}
