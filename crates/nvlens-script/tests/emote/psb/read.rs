#![allow(clippy::unwrap_used)]

use super::*;
use crate::emote::psb::{PSB_MAGIC, PsbNumber, PsbValue};
use nvlens_io::{BinaryReader, BinaryWriter};
use std::collections::BTreeMap;

#[test]
fn index_reader_never_requests_resource_bytes() {
    struct IndexOnly {
        data: Vec<u8>,
        resource_start: u64,
    }
    impl ReadAt for IndexOnly {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }
        fn read_at(&self, offset: u64, size: usize) -> std::io::Result<std::borrow::Cow<'_, [u8]>> {
            assert!(
                offset + size as u64 <= self.resource_start,
                "resource body read during index parsing"
            );
            Ok(std::borrow::Cow::Borrowed(
                &self.data[offset as usize..offset as usize + size],
            ))
        }
    }
    let data = minimal_psb_fixture();
    let resource_start = u64::from(BinaryReader::u32_le(&data[32..36]));
    let source = IndexOnly {
        data,
        resource_start,
    };
    let parsed = parse_source(&source, None).unwrap();
    assert_eq!(parsed.resources[0].offset, resource_start);
    assert_eq!(parsed.resources[0].size, 3);
}

#[test]
fn native_boolean_and_signed_integer_tags() {
    for (encoded, expected) in [
        (vec![2], PsbValue::Bool(true)),
        (vec![3], PsbValue::Bool(false)),
        (vec![5, 0x80], PsbValue::Number(PsbNumber::Integer(-128))),
        (
            vec![6, 0xff, 0xff],
            PsbValue::Number(PsbNumber::Integer(-1)),
        ),
        (
            vec![9, 0, 0, 0, 0, 0xff],
            PsbValue::Number(PsbNumber::Integer(-4_294_967_296)),
        ),
    ] {
        let mut data = minimal_psb_fixture();
        let start = data.len();
        data.extend_from_slice(&encoded);
        patch_u32(&mut data, 36, start);
        assert_eq!(parse_source(&data.as_slice(), None).unwrap().root, expected);
    }
}

#[test]
fn nested_lists_use_file_structure_instead_of_depth_thresholds() {
    let mut data = minimal_psb_fixture();
    let start = data.len();
    for _ in 0..10_000 {
        data.extend_from_slice(&[0x20, 0x0d, 1, 0x0d, 0]);
    }
    data.push(2);
    patch_u32(&mut data, 36, start);
    let parsed = parse_source(&data.as_slice(), None).unwrap();
    let mut node = &parsed.root;
    for _ in 0..10_000 {
        let children = node.as_list().unwrap();
        assert_eq!(children.len(), 1);
        node = &children[0];
    }
    assert_eq!(node, &PsbValue::Bool(true));
}

#[test]
fn truncated_inputs_and_unrelated_data_are_distinct() {
    let fixture = minimal_psb_fixture();
    for length in 0..fixture.len() {
        assert!(parse_source(&(&fixture[..length]), None).is_err());
    }
    assert!(matches!(
        parse_source(&(&b"other file"[..]), None),
        Err(Error::InvalidFormat)
    ));
}

#[test]
fn parses_minimal_psb_fixture() {
    let psb = minimal_psb_fixture();
    let parsed = parse_source(&psb.as_slice(), None).unwrap();
    assert_eq!(parsed.names, vec!["abcde"]);
    assert_eq!(parsed.strings, vec!["hello"]);
    assert_eq!(parsed.resources.len(), 1);
    let json: serde_json::Value = serde_json::from_str(&parsed.to_json().unwrap()).unwrap();
    assert_eq!(json["abcde"], "hello");

    assert!(matches!(parsed.root, PsbValue::Object(_)));
    let PsbValue::Object(root) = &parsed.root else {
        return;
    };
    assert_eq!(
        root.get("abcde"),
        Some(&PsbValue::String {
            index: 0,
            value: "hello".to_string()
        })
    );
}

#[test]
fn json_preserves_nested_values_escapes_and_resource_references() {
    let data = minimal_psb_fixture();
    let mut parsed = parse_source(&data.as_slice(), None).unwrap();
    parsed.root = PsbValue::Object(BTreeMap::from([
        (
            "quote\"\n日本語".into(),
            PsbValue::String {
                index: 0,
                value: "text\n\"\\\t".into(),
            },
        ),
        (
            "list".into(),
            PsbValue::List(vec![
                PsbValue::Null,
                PsbValue::Bool(false),
                PsbValue::Number(PsbNumber::Integer(i64::MIN)),
                PsbValue::Number(PsbNumber::Float(f32::from_bits(0x7fc01234))),
                PsbValue::Number(PsbNumber::Double(f64::NEG_INFINITY)),
                PsbValue::Array(vec![0, u32::MAX]),
                PsbValue::Resource {
                    index: 0,
                    is_extra: true,
                },
                PsbValue::Object(BTreeMap::new()),
                PsbValue::List(Vec::new()),
            ]),
        ),
    ]));
    let json: serde_json::Value = serde_json::from_str(&parsed.to_json().unwrap()).unwrap();
    assert_eq!(json["quote\"\n日本語"], "text\n\"\\\t");
    assert_eq!(json["list"][2], i64::MIN);
    assert_eq!(json["list"][3]["$float_bits"], 0x7fc01234u32);
    assert_eq!(json["list"][4]["$double_bits"], f64::NEG_INFINITY.to_bits());
    assert_eq!(json["list"][5][1], u32::MAX);
    assert_eq!(json["list"][6]["$resource"], 0);
    assert_eq!(json["list"][6]["$extra"], true);
    for _ in 0..256 {
        let child = std::mem::replace(&mut parsed.root, PsbValue::Null);
        parsed.root = PsbValue::List(vec![child]);
    }
    let text = parsed.to_json().unwrap();
    assert_eq!(text.matches('[').count(), text.matches(']').count());
}

fn minimal_psb_fixture() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PSB_MAGIC);
    push_u16(&mut out, 3);
    push_u16(&mut out, 0);
    push_u32(&mut out, 44);
    let offset_names_pos = out.len();
    push_u32(&mut out, 0);
    let offset_strings_pos = out.len();
    push_u32(&mut out, 0);
    let offset_strings_data_pos = out.len();
    push_u32(&mut out, 0);
    let offset_chunk_offsets_pos = out.len();
    push_u32(&mut out, 0);
    let offset_chunk_lengths_pos = out.len();
    push_u32(&mut out, 0);
    let offset_chunk_data_pos = out.len();
    push_u32(&mut out, 0);
    let offset_entries_pos = out.len();
    push_u32(&mut out, 0);
    push_u32(&mut out, 0);

    let offset_names = out.len();
    push_array(&mut out, &vec![0; 103]);
    let mut names_data = vec![0; 103];
    names_data[102] = 101;
    names_data[0] = 101;
    names_data[101] = 100;
    names_data[100] = 99;
    names_data[99] = 98;
    names_data[98] = 97;
    names_data[97] = 0;
    push_array(&mut out, &names_data);
    push_array(&mut out, &[102]);

    let offset_strings = out.len();
    push_array(&mut out, &[0]);

    let offset_strings_data = out.len();
    out.extend_from_slice(b"hello\0");

    let offset_chunk_offsets = out.len();
    push_array(&mut out, &[0]);

    let offset_chunk_lengths = out.len();
    push_array(&mut out, &[3]);

    let offset_entries = out.len();
    out.push(0x21);
    push_array(&mut out, &[0]);
    push_array(&mut out, &[0]);
    out.push(0x15);
    out.push(0);

    let offset_chunk_data = out.len();
    out.extend_from_slice(b"res");

    patch_u32(&mut out, offset_names_pos, offset_names);
    patch_u32(&mut out, offset_strings_pos, offset_strings);
    patch_u32(&mut out, offset_strings_data_pos, offset_strings_data);
    patch_u32(&mut out, offset_chunk_offsets_pos, offset_chunk_offsets);
    patch_u32(&mut out, offset_chunk_lengths_pos, offset_chunk_lengths);
    patch_u32(&mut out, offset_chunk_data_pos, offset_chunk_data);
    patch_u32(&mut out, offset_entries_pos, offset_entries);
    out
}

fn push_array(out: &mut Vec<u8>, values: &[u32]) {
    out.push(0x0D);
    out.push(u8::try_from(values.len()).unwrap());
    out.push(0x0D);
    for &value in values {
        out.push(u8::try_from(value).unwrap());
    }
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    let mut bytes = [0u8; 2];
    BinaryWriter::u16_le(value, &mut bytes);
    out.extend_from_slice(&bytes);
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    let mut bytes = [0u8; 4];
    BinaryWriter::u32_le(value, &mut bytes);
    out.extend_from_slice(&bytes);
}

fn patch_u32(out: &mut [u8], offset: usize, value: usize) {
    let value = u32::try_from(value).unwrap();
    BinaryWriter::u32_le_at(value, out, offset);
}
