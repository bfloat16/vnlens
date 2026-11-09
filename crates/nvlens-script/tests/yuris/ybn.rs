#![allow(clippy::unwrap_used)]

use super::*;
use nvlens_io::BinaryWriter;

fn fixture() -> Vec<u8> {
    let mut b = vec![0; 32];
    b[..4].copy_from_slice(b"YSTB");
    for (at, value) in [(4, 0x1ee), (8, 2), (12, 8), (16, 12), (20, 8), (24, 8)] {
        BinaryWriter::u32_le(value, &mut b[at..]);
    }
    b.extend_from_slice(&[106, 1, 0, 0, 255, 0, 7, 0]);
    let mut param = [0; 12];
    BinaryWriter::u32_le(8, &mut param[4..]);
    b.extend_from_slice(&param);
    b.extend_from_slice(b"Example!");
    for line in [12, 13] {
        let mut word = [0; 4];
        BinaryWriter::u32_le(line, &mut word);
        b.extend_from_slice(&word);
    }
    b
}

#[test]
fn xor_sections_and_lossless_unknown_instructions() {
    let bytes = fixture();
    let key = [1, 2, 3, 4];
    let mut encrypted = bytes.clone();
    decrypt_ystb(&mut encrypted, &key).unwrap();
    assert_ne!(encrypted, bytes);
    assert!(disassemble(&encrypted, None).is_err());
    decrypt_ystb(&mut encrypted, &key).unwrap();
    assert_eq!(encrypted, bytes);
    let ir = disassemble(&bytes, None).unwrap();
    assert_eq!(ir.instructions.len(), 2);
    assert_eq!(ir.instructions[1].opcode.code, 255);
    assert_eq!(ir.instructions[1].opcode.operation, Operation::Unknown);
    assert!(matches!(&ir.instructions[0].args[0].value,Value::Text(s) if s=="Example!"));
    assert_eq!(ir.instructions[0].span.offset, 0x20);
    assert_eq!(ir.instructions[0].source_line, Some(12));
    assert_eq!(
        ir.sections
            .iter()
            .flat_map(|section| section.raw.iter().copied())
            .collect::<Vec<_>>(),
        bytes
    );
    assert!(
        String::from_utf8(ir.to_json().unwrap())
            .unwrap()
            .contains("instruction")
    );
    for end in 0..bytes.len() {
        assert!(disassemble(&bytes[..end], None).is_err());
    }
}

#[test]
fn type_four_expressions_and_labels_are_resolved_only_when_referenced() {
    use std::cell::RefCell;
    struct Resources {
        calls: RefCell<Vec<String>>,
        labels: Vec<u8>,
    }
    impl ResourceResolver for Resources {
        fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
            self.calls.borrow_mut().push(name.into());
            Ok((name == "ysbin/ysl.ybn").then(|| self.labels.clone()))
        }
    }
    let mut label = vec![0; 12 + 1024];
    label[..4].copy_from_slice(b"YSLB");
    BinaryWriter::u32_le(0x1ee, &mut label[4..]);
    BinaryWriter::u32_le(1, &mut label[8..]);
    label.extend_from_slice(b"\x03abc");
    let at = label.len();
    label.resize(at + 12, 0);
    BinaryWriter::u32_le(0x1357_7c9b, &mut label[at..]);
    BinaryWriter::u32_le(42, &mut label[at + 4..]);
    BinaryWriter::u16_le(7, &mut label[at + 8..]);
    let resources = Resources {
        calls: RefCell::new(Vec::new()),
        labels: label,
    };
    let mut bytes = fixture();
    bytes[32] = 44;
    bytes[42] = 4;
    bytes[52..60].copy_from_slice(b"M\x05\x00\"abc\"");
    let ir = disassemble(&bytes, Some(&resources)).unwrap();
    assert!(
        matches!(&ir.instructions[0].args[0].value, Value::Expression(t)
        if matches!(&t[0].args.first().map(|arg| &arg.value),Some(Value::Text(s)) if s == "abc"))
    );
    assert!(matches!(&ir.instructions[0].args[1].value,
        Value::ResourceInstructionTarget { resource, instruction: 42, symbol }
        if resource == "ysbin/yst00007.ybn" && symbol == "abc"));
    assert_eq!(
        *resources.calls.borrow(),
        ["ysbin/ysc.ybn", "ysbin/ysl.ybn"]
    );
    resources.calls.borrow_mut().clear();
    disassemble(&fixture(), Some(&resources)).unwrap();
    assert_eq!(*resources.calls.borrow(), ["ysbin/ysc.ybn"]);
}

#[test]
fn control_descriptors_are_not_data_slices_and_targets_are_checked() {
    let mut bytes = fixture();
    bytes[32] = 79;
    BinaryWriter::u32_le(0x12345678, &mut bytes[40..]);
    BinaryWriter::u32_le(u32::MAX, &mut bytes[44..]);
    let ir = disassemble(&bytes, None).unwrap();
    assert!(
        matches!(&ir.instructions[0].args[0].value,Value::Group(fields)
        if matches!(fields[0].value, Value::Unsigned(0x12345678)))
    );
    bytes[32] = 45;
    bytes[33] = 2;
    bytes[42] = 1;
    BinaryWriter::u32_le(8, &mut bytes[44..]);
    bytes[52..60].copy_from_slice(b"M\x05\x00\"abc\"");
    bytes.splice(52..52, [0; 12]);
    BinaryWriter::u32_le(24, &mut bytes[16..]);
    BinaryWriter::u32_le(1, &mut bytes[56..]);
    BinaryWriter::u32_le(u32::MAX, &mut bytes[60..]);
    assert!(disassemble(&bytes, None).is_ok());
    BinaryWriter::u32_le(3, &mut bytes[56..]);
    assert!(disassemble(&bytes, None).is_err());
}
