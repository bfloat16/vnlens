#![allow(clippy::unwrap_used)]
use super::*;
use vnlens_io::BinaryWriter;

fn document(code: &[u8], newer: bool) -> Vec<u8> {
    let mut out = vec![0; 64];
    out[..8].copy_from_slice(b"Entis\x1a\0\0");
    BinaryWriter::u32_le(u32::MAX, &mut out[8..]);
    let description = b"Cotopha Image file\0";
    out[16..16 + description.len()].copy_from_slice(description);
    if newer {
        out.extend(b"header  ");
        let mut length = [0; 8];
        BinaryWriter::u64_le(36, &mut length);
        out.extend(length);
        out.extend([0; 36]);
    }
    out.extend(b"image   ");
    let mut length = [0; 8];
    BinaryWriter::u64_le(code.len() as u64, &mut length);
    out.extend(length);
    out.extend(code);
    out
}

#[test]
fn classic_integer_and_sakura_ieee_bits_keep_spans() {
    let mut code = vec![2, 0, 4];
    let mut integer = [0; 4];
    BinaryWriter::u32_le(42, &mut integer);
    code.extend(integer);
    code.extend([9, 1]);
    let script = Csx
        .disassemble(&document(&code, false), None)
        .unwrap()
        .unwrap();
    assert_eq!(script.instructions.len(), 2);
    assert!(matches!(
        script.instructions[0].args[2].value,
        Value::Integer(42)
    ));
    assert_eq!(script.instructions[0].span.offset, 80);
    let mut code = vec![0x9b, 1];
    let mut bits = [0; 8];
    BinaryWriter::u64_le(0x7ff8000000000123, &mut bits);
    code.extend(bits);
    code.push(0xd8);
    let script = Csx
        .disassemble(&document(&code, true), None)
        .unwrap()
        .unwrap();
    assert_eq!(script.instructions[0].opcode.namespace, "sakura2");
    assert_eq!(
        script.instructions[0].opcode.native_mnemonic.as_deref(),
        Some("move")
    );
    assert!(matches!(
        script.instructions[0].args[1].value,
        Value::Unsigned(0x7ff8000000000123)
    ));
}

#[test]
fn truncation_and_cancellation_stop_disassembly() {
    assert!(
        matches!(Csx.disassemble(&document(&[2, 0, 4, 1], false), None), Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof)
    );
    assert!(matches!(
        Csx.disassemble_cancellable(&[], None, &Default::default(), &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    assert_eq!(
        Text.decode_text(b"ASCII source\n").unwrap().unwrap(),
        "ASCII source\n"
    );
}

#[test]
fn unknown_function_length_and_external_address_are_native_sentinels() {
    let mut bytes = document(&[9, 1], true);
    let mut info = vec![0; 4];
    BinaryWriter::u32_le(2, &mut info);
    for address in [0, u32::MAX] {
        let mut row = vec![0; 20];
        BinaryWriter::u32_le(address, &mut row[4..]);
        BinaryWriter::u32_le(u32::MAX, &mut row[8..]);
        info.extend(row);
    }
    bytes.extend(b"funcinfo");
    let mut size = [0; 8];
    BinaryWriter::u64_le(info.len() as u64, &mut size);
    bytes.extend(size);
    bytes.extend(info);
    let script = Csx.disassemble(&bytes, None).unwrap().unwrap();
    assert_eq!(script.instructions.len(), 1);
    assert_eq!(script.instructions[0].opcode.code, 9);
}
