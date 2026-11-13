#![allow(clippy::unwrap_used)]

use super::*;
use vnlens_io::BinaryWriter;

fn token(code: u8, raw: &[u8]) -> Vec<u8> {
    let mut bytes = vec![code, 0, 0];
    BinaryWriter::u16_le(raw.len() as u16, &mut bytes[1..]);
    bytes.extend_from_slice(raw);
    bytes
}

#[test]
fn decodes_vm_strings_without_confusing_cp932_trail_bytes() {
    let raw = b"\"a\\nb\\tc\\\\d\x83\x5c\"";
    let bytes = token(b'M', raw);
    let tokens = decode(&bytes, 0x100).unwrap();
    assert!(
        matches!(&tokens[0].args.first().map(|arg| &arg.value), Some(Value::Text(s)) if s == "a\nb\tc\\dソ")
    );
    assert_eq!(tokens[0].raw, raw);
    assert_eq!(tokens[0].span.offset, 0x100);
    assert!(matches!(string(b"'quote: \"'", 0).unwrap(), Value::Text(text) if text == "quote: \""));
    // 0x426930 drops an unrecognized escape's slash and reprocesses its
    // following byte, including a closing delimiter.
    assert!(matches!(string(b"\"a\\qb\"", 0).unwrap(), Value::Text(text) if text == "aqb"));
    assert!(matches!(string(b"\"a\\\"", 0).unwrap(), Value::Text(text) if text == "a"));
    assert!(string(b"\"a\\", 0).is_err());
    assert!(string(b"\"unclosed", 0).is_err());
    assert!(string(b"\"closed\"extra", 0).is_err());
    assert!(string(b"\"\x83", 0).is_err());
    for end in 1..bytes.len() {
        assert!(decode(&bytes[..end], 0).is_err());
    }
}

#[test]
fn project_font_codes_remain_bytes_without_discarding_the_script() {
    let raw = b"\"a\xef\xf0b\"";
    let tokens = decode(&token(b'M', raw), 0).unwrap();
    assert!(matches!(&tokens[0].args[0].value,Value::Bytes(bytes) if bytes==b"a\xef\xf0b"));
    assert_eq!(tokens[0].raw, raw);
    assert!(string(b"\"a\xef\xf0b", 0).is_err());
}

#[test]
fn identifies_variables_and_distinguishes_logical_and_bitwise_operations() {
    let mut raw = vec![b'@', 0, 0];
    BinaryWriter::u16_le(0x1234, &mut raw[1..]);
    let tokens = decode(&token(b'H', &raw), 0x80).unwrap();
    assert!(matches!(tokens[0].args[1].value, Value::Unsigned(0x1234)));
    assert_eq!(tokens[0].args[1].span.offset, 0x84);
    for (code, name) in [
        (b'!', "not_equal"),
        (b'&', "logical_and"),
        (b'|', "logical_or"),
        (b'A', "bit_and"),
        (b'O', "bit_or"),
        (b'R', "negate"),
        (b'S', "less_equal"),
        (b'Z', "greater_equal"),
    ] {
        assert_eq!(
            decode(&token(code, &[]), 0).unwrap()[0]
                .opcode
                .operation
                .name(),
            name
        );
    }
    assert!(decode(&token(b'H', &[1, 2]), 0).is_err());
    assert!(decode(&token(b'+', &[1]), 0).is_err());
    let unknown = decode(&token(0xfe, &[1, 2]), 0).unwrap();
    assert_eq!(unknown[0].opcode.operation, Operation::Unknown);
    assert_eq!(unknown[0].raw, [1, 2]);
}

#[test]
fn keeps_signed_constants_and_exact_float_bits() {
    let signed = decode(&token(b'B', &[0xff]), 0).unwrap();
    assert!(matches!(
        signed[0].args.first().map(|arg| &arg.value),
        Some(Value::Integer(-1))
    ));
    let bits = 0x7ff8_0000_0000_0042;
    let mut raw = [0; 8];
    BinaryWriter::u64_le(bits, &mut raw);
    assert!(
        matches!(decode(&token(b'F', &raw), 0).unwrap()[0].args.first().map(|arg| &arg.value), Some(Value::Float64Bits(v)) if *v == bits)
    );
}
