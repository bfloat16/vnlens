#![allow(clippy::unwrap_used)]

use super::*;
use vnlens_io::{BinaryWriter, Endian};

fn word(bytes: &mut Vec<u8>, n: u32, endian: Endian) {
    let mut out = [0; 4];
    match endian {
        Endian::Little => BinaryWriter::u32_le(n, &mut out),
        Endian::Big => BinaryWriter::u32_be(n, &mut out),
    }
    bytes.extend(out);
}
fn wide(bytes: &mut Vec<u8>, n: u64, endian: Endian) {
    let mut out = [0; 8];
    match endian {
        Endian::Little => BinaryWriter::u64_le(n, &mut out),
        Endian::Big => BinaryWriter::u64_be(n, &mut out),
    }
    bytes.extend(out);
}
fn header(endian: Endian) -> Vec<u8> {
    let mut bytes = b"\x1bLua\x53\0\x19\x93\r\n\x1a\n\x04\x08\x04\x08\x08".to_vec();
    wide(&mut bytes, 0x5678, endian);
    wide(&mut bytes, 370.5f64.to_bits(), endian);
    bytes.push(0);
    bytes
}
fn prefix(bytes: &mut Vec<u8>, endian: Endian) {
    bytes.push(0); // Inherited source string.
    word(bytes, 0, endian);
    word(bytes, 0, endian);
    bytes.extend([0, 0, 2]);
}
fn debug(bytes: &mut Vec<u8>, endian: Endian) {
    for _ in 0..3 {
        word(bytes, 0, endian);
    }
}

#[test]
fn endian_constants_and_original_instruction_ranges() {
    for endian in [Endian::Little, Endian::Big] {
        let mut bytes = header(endian);
        prefix(&mut bytes, endian);
        word(&mut bytes, 1, endian);
        let at = bytes.len();
        word(&mut bytes, 0x0080_0026, endian); // RETURN A=0 B=1.
        word(&mut bytes, 4, endian);
        bytes.extend([0, 1, 1, 19]);
        wide(&mut bytes, (-123i64) as u64, endian);
        bytes.push(3);
        wide(&mut bytes, 0x7ff8_0000_0000_1234, endian);
        word(&mut bytes, 0, endian); // Upvalues.
        word(&mut bytes, 0, endian); // Children.
        debug(&mut bytes, endian);
        let chunk = read(&bytes).unwrap();
        let f = &chunk.functions[0];
        assert_eq!(f.code_range, at..at + 4);
        assert_eq!(f.code, [0x0080_0026]);
        assert!(matches!(
            f.constants.as_slice(),
            [
                Constant::Nil,
                Constant::Boolean(true),
                Constant::Integer(-123),
                Constant::Float64(0x7ff8_0000_0000_1234)
            ]
        ));
        let ir = super::super::disasm::parse(&bytes).unwrap();
        assert_eq!(ir.instructions[1].span.offset, at as u64);
        assert_eq!(
            ir.instructions[1].opcode.operation,
            crate::ir::Operation::Native
        );
        assert_eq!(ir.sections[0].raw, bytes);
        assert!(
            matches!(read(&bytes[..bytes.len()-1]), Err(vnlens_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof)
        );
    }
}

#[test]
fn deeply_nested_functions_parse_and_drop_without_recursion() {
    let endian = Endian::Little;
    let mut bytes = header(endian);
    let depth = 4096;
    for index in 0..depth {
        prefix(&mut bytes, endian);
        for _ in 0..3 {
            word(&mut bytes, 0, endian);
        } // Code, constants, upvalues.
        word(&mut bytes, u32::from(index + 1 < depth), endian);
    }
    for _ in 0..depth {
        debug(&mut bytes, endian);
    }
    let chunk = read(&bytes).unwrap();
    assert_eq!(chunk.functions.len(), depth);
    assert_eq!(chunk.functions[depth - 1].parent, Some((depth - 2, 0)));
    drop(chunk);
    bytes.pop();
    assert!(read(&bytes).is_err());
}

fn lua54(code: &[u32]) -> Vec<u8> {
    let mut bytes = b"\x1bLua\x54\0\x19\x93\r\n\x1a\n\x04\x08\x08".to_vec();
    wide(&mut bytes, 0x5678, Endian::Little);
    wide(&mut bytes, 370.5f64.to_bits(), Endian::Little);
    bytes.extend([0, 0x80, 0x80, 0x80, 0, 0, 2, 0x80 | code.len() as u8]);
    for &n in code {
        word(&mut bytes, n, Endian::Little);
    }
    bytes.extend([0x80; 7]);
    bytes
}

fn lua55(code: &[u32]) -> Vec<u8> {
    let mut bytes = b"\x1bLua\x55\0\x19\x93\r\n\x1a\n\x04".to_vec();
    word(&mut bytes, (-0x5678i32) as u32, Endian::Little);
    bytes.push(4);
    word(&mut bytes, 0x1234_5678, Endian::Little);
    bytes.push(8);
    wide(&mut bytes, (-0x5678i64) as u64, Endian::Little);
    bytes.push(8);
    wide(&mut bytes, (-370.5f64).to_bits(), Endian::Little);
    bytes.extend([0, 0, 0, 0, 0, 2, code.len() as u8]);
    let pad = (4 - bytes.len() % 4) % 4;
    bytes.resize(bytes.len() + pad, 0);
    for &n in code {
        word(&mut bytes, n, Endian::Little);
    }
    bytes.extend([0; 9]);
    bytes
}

#[test]
fn lua54_and_lua55_forprep_and_variable_width_fields() -> Result<()> {
    use crate::ir::{ArgName, Operation, Value};
    // FORPREP A=0 Bx=1: fetched PC + Bx + 1, hence original PC + 3.
    let forprep = 74 | (1 << 15);
    for bytes in [
        lua54(&[forprep, 0, 0, 71 | (1 << 16)]),
        lua55(&[forprep, 0, 0, 71 | (1 << 16)]),
    ] {
        let parsed = super::super::disasm::parse(&bytes)?;
        let offset = parsed.instructions[1].span.offset;
        assert_eq!(parsed.instructions[1].opcode.operation, Operation::Native);
        assert!(
            parsed.instructions[1]
                .args
                .iter()
                .any(|o| o.name == ArgName::Target
                    && matches!(o.value, Value::CodeAddress(a) if a == offset + 12))
        );
    }
    // NEWTABLE A=0 vB=2 vC=513 k=0, followed by its required EXTRAARG.
    let parsed =
        super::super::disasm::parse(&lua55(&[19 | (2 << 16) | (513 << 22), 84, 71 | (1 << 16)]))?;
    let args = &parsed.instructions[1].args;
    assert_eq!(args[1].native_name.as_deref(), Some("vB"));
    assert!(matches!(args[1].value, Value::Integer(2)));
    assert_eq!(args[2].native_name.as_deref(), Some("vC"));
    assert!(matches!(args[2].value, Value::Integer(513)));
    // ERRNNIL Bx=0 is an unavailable diagnostic name, not constant 0.
    let parsed = super::super::disasm::parse(&lua55(&[82, 71 | (1 << 16)]))?;
    assert!(matches!(
        parsed.instructions[1].args[1].value,
        Value::Integer(0)
    ));
    Ok(())
}
