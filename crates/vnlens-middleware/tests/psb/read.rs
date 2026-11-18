#![allow(clippy::unwrap_used)]

use super::*;
use crate::psb::{PSB_MAGIC, PsbNumber, PsbValue};
use std::collections::BTreeMap;
use vnlens_io::{BinaryReader, BinaryWriter};

// A synthetic one-key double-array trie with a string value. Each path node
// receives its own byte alphabet, so shared byte values cannot alias parents.
fn text_fixture(version: u16, name: &[u8], text: &[u8]) -> Vec<u8> {
    let mut data = vec![0; super::super::header::header_len(version)];
    data[..4].copy_from_slice(PSB_MAGIC);
    BinaryWriter::u16_le(version, &mut data[4..]);
    let keys = data.len();
    if version == 1 {
        array(&mut data, &[0], 1, 1);
    }
    let names = data.len();
    if version == 1 {
        data.extend_from_slice(name);
        data.push(0);
    } else {
        let leaf = name.len() * 256;
        let mut bases = vec![0; leaf + 1];
        let mut parents = bases.clone();
        let mut parent = 0;
        for (index, &byte) in name.iter().enumerate() {
            bases[parent] = (index * 256) as u64;
            let node = index * 256 + usize::from(byte);
            parents[node] = parent as u64;
            parent = node;
        }
        bases[parent] = leaf as u64;
        parents[leaf] = parent as u64;
        array(&mut data, &bases, 2, 2);
        array(&mut data, &parents, 2, 2);
        array(&mut data, &[leaf as u64], 1, 2);
    }
    let strings = data.len();
    array(&mut data, &[0], 1, 1);
    let string_data = data.len();
    data.extend_from_slice(text);
    data.push(0);
    let entries = data.len();
    if version == 1 {
        data.extend([0x21, 0x0d, 1, 0x0d, 0, 0x11, 0, 0x15, 0]);
    } else {
        data.extend([0x21, 0x0d, 1, 0x0d, 0, 0x0d, 1, 0x0d, 0, 0x15, 0]);
    }
    let chunks = data.len();
    array(&mut data, &[], 1, 1);
    let end = data.len();
    for (at, value) in [
        (8, keys),
        (12, names),
        (16, strings),
        (20, string_data),
        (24, chunks),
        (28, chunks),
        (32, end),
        (36, entries),
    ] {
        patch_u32(&mut data, at, value);
    }
    if version == 4 {
        patch_u32(&mut data, 44, chunks);
        patch_u32(&mut data, 48, chunks);
        patch_u32(&mut data, 52, end);
    }
    if version >= 3 {
        let mut checksum = vnlens_crypto::checksum::adler32::Adler32::default();
        checksum.update(&data[8..40]);
        if version == 4 {
            checksum.update(&data[44..56]);
        }
        BinaryWriter::u32_le(checksum.checksum(), &mut data[40..]);
    }
    data
}

#[test]
fn cesu8_names_and_strings_keep_emoji_without_replacement() -> Result<()> {
    let encoded = b"key\xed\xa0\xbd\xed\xb8\x85_ase";
    let expected = "key😅_ase";
    for version in 1..=4 {
        for name in [encoded.as_slice(), expected.as_bytes()] {
            let data = text_fixture(version, name, encoded);
            let psb = parse_source(&data.as_slice(), None)?;
            assert_eq!(psb.names, [expected]);
            assert_eq!(psb.strings, [expected]);
            assert_eq!(
                psb.root.as_object().unwrap()[expected].as_str(),
                Some(expected)
            );
            let json: serde_json::Value = serde_json::from_str(&psb.to_json()?).unwrap();
            assert_eq!(json[expected], expected);
        }
        for invalid in [
            b"\xed\xa0\xbd".as_slice(),
            b"\xff".as_slice(),
            b"\xed\xb8\x85\xed\xa0\xbd".as_slice(),
        ] {
            for (name, text) in [(invalid, b"ok".as_slice()), (b"ok".as_slice(), invalid)] {
                let data = text_fixture(version, name, text);
                assert!(matches!(
                    parse_source(&data.as_slice(), None),
                    Err(Error::Corrupt { .. })
                ));
            }
        }
    }
    Ok(())
}

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
            Ok(std::borrow::Cow::Owned(
                self.data[offset as usize..offset as usize + size].to_vec(),
            ))
        }
    }
    let values: Vec<_> = (0..70_001).map(|index| index % 65536).collect();
    let mut root = Vec::new();
    array(&mut root, &values, 4, 2);
    for data in [minimal_psb_fixture(), version_fixture(3, &root, 0)] {
        let resource_start = u64::from(BinaryReader::u32_le(&data[32..36]));
        let source = IndexOnly {
            data,
            resource_start,
        };
        let parsed = parse_source(&source, None).unwrap();
        assert_eq!(parsed.resources[0].offset, resource_start);
        assert_eq!(parsed.resources[0].size, 3);
        if let PsbValue::Array(decoded) = &parsed.root {
            assert_eq!(decoded, &values);
        }
    }
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
                PsbValue::Array(vec![0, u64::MAX]),
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
    assert_eq!(json["list"][5][1], u64::MAX);
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

fn array(out: &mut Vec<u8>, values: &[u64], count_width: usize, entry_width: usize) {
    out.push(0x0c + count_width as u8);
    let start = out.len();
    out.resize(start + count_width, 0);
    BinaryWriter::compact_u64_le(values.len() as u64, &mut out[start..]).unwrap();
    out.push(0x0c + entry_width as u8);
    for &value in values {
        let start = out.len();
        out.resize(start + entry_width, 0);
        BinaryWriter::compact_u64_le(value, &mut out[start..]).unwrap();
    }
}

// Names are one v1 key or a v2+ trie for "a". The tree precedes chunk tables
// so body encryption covers names, strings and values, never resource bytes.
pub(in crate::psb) fn version_fixture(version: u16, root: &[u8], padding: usize) -> Vec<u8> {
    let size = super::super::header::header_len(version);
    let mut bytes = vec![0; size + padding];
    bytes[..4].copy_from_slice(PSB_MAGIC);
    BinaryWriter::u16_le(version, &mut bytes[4..]);
    let keys = bytes.len();
    if version == 1 {
        array(&mut bytes, &[0], 1, 1);
    }
    let names = bytes.len();
    if version == 1 {
        bytes.extend_from_slice(b"a\0");
    } else {
        array(&mut bytes, &[0], 1, 1);
        let mut trie = vec![0; 99];
        trie[98] = 97;
        array(&mut bytes, &trie, 1, 1);
        array(&mut bytes, &[98], 1, 1);
    }
    let strings = bytes.len();
    array(&mut bytes, &[0], 1, 1);
    let string_data = bytes.len();
    bytes.extend_from_slice("日本語\0".as_bytes());
    let entries = bytes.len();
    bytes.extend_from_slice(root);
    let mut extra = None;
    if version == 4 {
        let offsets = bytes.len();
        array(&mut bytes, &[0], 1, 1);
        let lengths = bytes.len();
        array(&mut bytes, &[5], 1, 1);
        let data = bytes.len();
        bytes.extend_from_slice(b"extra");
        extra = Some((offsets, lengths, data));
    }
    let offsets = bytes.len();
    array(&mut bytes, &[0], 1, 1);
    let lengths = bytes.len();
    array(&mut bytes, &[3], 1, 1);
    let resource_data = bytes.len();
    bytes.extend_from_slice(b"res");
    if let Some((offsets, lengths, data)) = extra {
        patch_u32(&mut bytes, 44, offsets);
        patch_u32(&mut bytes, 48, lengths);
        patch_u32(&mut bytes, 52, data);
    }
    for (at, value) in [
        (8, keys),
        (12, names),
        (16, strings),
        (20, string_data),
        (24, offsets),
        (28, lengths),
        (32, resource_data),
        (36, entries),
    ] {
        patch_u32(&mut bytes, at, value);
    }
    if version >= 3 {
        let mut checksum = vnlens_crypto::checksum::adler32::Adler32::default();
        checksum.update(&bytes[8..40]);
        if version == 4 {
            checksum.update(&bytes[44..56]);
        }
        BinaryWriter::u32_le(checksum.checksum(), &mut bytes[40..]);
    }
    bytes
}

#[test]
fn versions_padding_header_fields_and_v1_unsigned_keys() {
    for version in 1..=4 {
        for padding in [0, 1024] {
            let root: &[u8] = if version == 1 {
                &[0x21, 0x0d, 1, 0x0d, 0, 0x11, 0, 0x15, 0]
            } else {
                &[0x21, 0x0d, 1, 0x0d, 0, 0x0d, 1, 0x0d, 0, 0x15, 0]
            };
            let mut data = version_fixture(version, root, padding);
            BinaryWriter::u16_le(0x8000, &mut data[6..]);
            let psb = parse_source(&data.as_slice(), None).unwrap();
            assert_eq!(psb.header.version, version);
            assert_eq!(psb.header.flags, 0x8000);
            assert_eq!(psb.names, ["a"]);
            assert_eq!(psb.strings, ["日本語"]);
            assert_eq!(psb.root.as_object().unwrap()["a"].as_str(), Some("日本語"));
            assert_eq!(psb.resources[0].size, 3);
            assert_eq!(psb.extra_resources.len(), usize::from(version == 4));
            assert_eq!(psb.header.checksum_valid(), (version >= 3).then_some(true));
            let node = &psb.nodes[&u64::from(psb.header.offset_entries)];
            assert_eq!(node.tag, 0x21);
            assert_eq!(node.children[0].name_index, Some(0));
            assert_eq!(node.children[0].key_offset.is_some(), version == 1);
        }
    }
}

#[test]
fn every_serialized_tag_and_compact_array_width_is_preserved() {
    for tag in 0..=0x25 {
        let mut root = vec![tag];
        match tag {
            5..=0x0c => root.resize(usize::from(tag - 4) + 1, 0xff),
            0x0d..=0x14 => {
                root.clear();
                array(&mut root, &[u64::MAX], usize::from(tag - 0x0c), 8);
            }
            0x15..=0x1c => root.resize(usize::from((tag - 0x15) % 4) + 2, 0),
            0x1e => {
                let mut bytes = [0; 4];
                BinaryWriter::u32_le(0x8000_0000, &mut bytes);
                root.extend(bytes);
            }
            0x1f => {
                let mut bytes = [0; 8];
                BinaryWriter::u64_le(0x7ff8_0000_0000_1234, &mut bytes);
                root.extend(bytes);
            }
            0x20 => array(&mut root, &[], 1, 1),
            0x21 => {
                array(&mut root, &[], 1, 1);
                array(&mut root, &[], 1, 1);
            }
            0x22..=0x25 => root.resize(usize::from(tag - 0x22) + 2, 0),
            _ => {}
        }
        let data = version_fixture(4, &root, 0);
        let psb = parse_source(&data.as_slice(), None).unwrap();
        let node = &psb.nodes[&u64::from(psb.header.offset_entries)];
        assert_eq!(node.tag, tag);
        assert_eq!(node.size, root.len() as u64);
        match tag {
            0 => assert_eq!(psb.root, PsbValue::Void),
            1 => assert_eq!(psb.root, PsbValue::Null),
            2 | 3 => assert_eq!(psb.root, PsbValue::Bool(tag == 2)),
            4 => assert_eq!(psb.root.as_i64(), Some(0)),
            5..=0x0c => assert_eq!(psb.root.as_i64(), Some(-1)),
            0x0d..=0x14 => assert_eq!(psb.root, PsbValue::Array(vec![u64::MAX])),
            0x15..=0x18 => assert_eq!(psb.root.as_str(), Some("日本語")),
            0x19..=0x1c | 0x22..=0x25 => assert_eq!(
                psb.root,
                PsbValue::Resource {
                    index: 0,
                    is_extra: tag >= 0x22
                }
            ),
            0x1d => assert_eq!(psb.root, PsbValue::Number(PsbNumber::Float(0.))),
            0x1e => assert!(
                matches!(psb.root, PsbValue::Number(PsbNumber::Float(value)) if value.to_bits() == 0x8000_0000)
            ),
            0x1f => assert!(
                matches!(psb.root, PsbValue::Number(PsbNumber::Double(value)) if value.to_bits() == 0x7ff8_0000_0000_1234)
            ),
            0x20 => assert_eq!(psb.root.as_list().unwrap().len(), 0),
            0x21 => assert_eq!(psb.root.as_object().unwrap().len(), 0),
            _ => {}
        }
    }
    for count_width in 1..=8 {
        for width in 1..=8 {
            let maximum = u64::MAX >> (64 - width * 8);
            let mut root = Vec::new();
            array(&mut root, &[0, 1, maximum], count_width, width);
            let data = version_fixture(3, &root, 0);
            assert_eq!(
                parse_source(&data.as_slice(), None).unwrap().root,
                PsbValue::Array(vec![0, 1, maximum])
            );
        }
    }
}

#[test]
fn shared_children_keep_their_source_identity() {
    let mut root = vec![0x20];
    array(&mut root, &[0, 0], 1, 1);
    root.push(2);
    let data = version_fixture(3, &root, 0);
    let psb = parse_source(&data.as_slice(), None).unwrap();
    assert_eq!(
        psb.root.as_list().unwrap(),
        &[PsbValue::Bool(true), PsbValue::Bool(true)]
    );
    assert_eq!(psb.nodes.len(), 2);
    let children = &psb.nodes[&u64::from(psb.header.offset_entries)].children;
    assert_eq!(children[0].offset, children[1].offset);
}

#[test]
fn shared_nodes_are_read_once_in_source_order_without_resource_reads() {
    use std::sync::Mutex;
    let root = [
        0x20, 0x0d, 2, 0x0d, 0, 5, 0x20, 0x0d, 1, 0x0d, 5, 0x20, 0x0d, 1, 0x0d, 0, 2,
    ];
    struct IndexOnly {
        bytes: Vec<u8>,
        root: u64,
        tree_end: u64,
        resource: u64,
        reads: Mutex<Vec<(u64, usize)>>,
    }
    impl ReadAt for IndexOnly {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn read_at(&self, offset: u64, size: usize) -> std::io::Result<std::borrow::Cow<'_, [u8]>> {
            assert!(offset + size as u64 <= self.resource);
            if offset < self.tree_end && offset + size as u64 > self.root {
                self.reads.lock().unwrap().push((offset, size));
            }
            self.bytes
                .as_slice()
                .read_at(offset, size)
                .map(|bytes| std::borrow::Cow::Owned(bytes.into_owned()))
        }
    }
    let bytes = version_fixture(3, &root, 0);
    let root_offset = u64::from(BinaryReader::u32_le(&bytes[36..]));
    let source = IndexOnly {
        resource: u64::from(BinaryReader::u32_le(&bytes[32..])),
        root: root_offset,
        tree_end: root_offset + root.len() as u64,
        bytes,
        reads: Mutex::default(),
    };
    let psb = parse_source(&source, None).unwrap();
    assert_eq!(psb.nodes.len(), 4);
    let lists = psb.root.as_list().unwrap();
    assert_eq!(lists.len(), 2);
    for list in lists {
        assert_eq!(list.as_list().unwrap(), &[PsbValue::Bool(true)]);
    }
    let reads = source.reads.lock().unwrap();
    assert!(reads.windows(2).all(|pair| pair[0].0 <= pair[1].0));
    assert_eq!(
        reads
            .iter()
            .filter(|&&(at, size)| {
                at <= root_offset + 16 && root_offset + 16 < at + size as u64
            })
            .count(),
        1
    );
}

fn encrypt_fixture(data: &mut [u8], mode: crate::psb::PsbEncryption, key: u32) {
    use crate::psb::PsbEncryption;
    use vnlens_crypto::cipher::psb_stream::PsbStream;
    let version = BinaryReader::u16_le(&data[4..]);
    let header_end = super::super::header::header_len(version);
    let start = BinaryReader::u32_le(&data[if version == 1 { 8 } else { 12 }..]) as usize;
    let end = BinaryReader::u32_le(&data[24..]) as usize;
    let mut cipher = PsbStream::new(key);
    if matches!(mode, PsbEncryption::Header | PsbEncryption::Full) {
        BinaryWriter::u16_le(1, &mut data[6..]);
        cipher.apply(&mut data[8..header_end]);
    }
    if matches!(mode, PsbEncryption::Body | PsbEncryption::Full) {
        cipher.apply(&mut data[start..end]);
    }
}

#[test]
fn independent_header_body_and_full_encryption_leave_payloads_unread() {
    use crate::psb::PsbEncryption;
    struct MetadataOnly {
        bytes: Vec<u8>,
        limit: u64,
    }
    impl ReadAt for MetadataOnly {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn read_at(&self, offset: u64, size: usize) -> std::io::Result<std::borrow::Cow<'_, [u8]>> {
            assert!(offset + size as u64 <= self.limit);
            self.bytes
                .as_slice()
                .read_at(offset, size)
                .map(|v| std::borrow::Cow::Owned(v.into_owned()))
        }
    }
    let key = 0x1234_5678;
    for version in 1..=4 {
        for mode in [
            PsbEncryption::None,
            PsbEncryption::Header,
            PsbEncryption::Body,
            PsbEncryption::Full,
        ] {
            let mut data = version_fixture(version, &[0x15, 0], 19);
            let limit = u64::from(BinaryReader::u32_le(&data[32..]));
            encrypt_fixture(&mut data, mode, key);
            let source = MetadataOnly { bytes: data, limit };
            let psb = parse_source(&source, Some(key)).unwrap();
            assert_eq!(psb.encryption, mode);
            assert_eq!(psb.root.as_str(), Some("日本語"));
            assert_eq!(psb.resources[0].offset, limit);
            if mode != PsbEncryption::None {
                assert!(matches!(
                    parse_source(&source, None),
                    Err(Error::UnknownScheme(_))
                ));
                assert!(parse_source(&source, Some(key + 1)).is_err());
            }
            let explicit = parse_source_with_options(
                &source,
                ParseOptions {
                    psb_key: Some(key),
                    encryption: mode,
                    ..ParseOptions::default()
                },
            )
            .unwrap();
            assert_eq!(explicit.root, psb.root);
        }
    }
}

#[test]
fn chunk_tables_retain_64_bit_ranges_without_reading_sparse_resources() {
    struct Sparse {
        prefix: Vec<u8>,
        len: u64,
    }
    impl ReadAt for Sparse {
        fn len(&self) -> u64 {
            self.len
        }
        fn read_at(&self, offset: u64, size: usize) -> std::io::Result<std::borrow::Cow<'_, [u8]>> {
            let end = offset.checked_add(size as u64).unwrap();
            assert!(
                end <= self.prefix.len() as u64,
                "sparse resource payload was read"
            );
            Ok(std::borrow::Cow::Borrowed(
                &self.prefix[offset as usize..end as usize],
            ))
        }
    }
    let mut data = version_fixture(3, &[0x19, 0], 0);
    let offsets = data.len();
    array(&mut data, &[0x1_0000_0000], 1, 8);
    let lengths = data.len();
    array(&mut data, &[0x2_0000_0000], 1, 8);
    patch_u32(&mut data, 24, offsets);
    patch_u32(&mut data, 28, lengths);
    let base = data.len();
    patch_u32(&mut data, 32, base);
    let source = Sparse {
        prefix: data,
        len: base as u64 + 0x3_0000_0000,
    };
    let psb = parse_source(&source, None).unwrap();
    assert_eq!(psb.resources[0].offset, base as u64 + 0x1_0000_0000);
    assert_eq!(psb.resources[0].size, 0x2_0000_0000);
}

#[test]
fn malformed_tags_counts_references_checksums_and_integer_widths() {
    for root in [
        vec![0x26],
        vec![0xff],
        vec![0x0d, 1, 0x0c],
        vec![0x0d, 1, 0x15],
        vec![0x14, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x14],
        vec![0x15, 1],
        vec![0x19, 1],
        vec![0x22, 1],
        vec![0x20, 0x0d, 1, 0x0d, 0xff],
        vec![0x21, 0x0d, 1, 0x0d, 0, 0x0d, 0, 0x0d],
        vec![0x21, 0x0d, 1, 0x0d, 1, 0x0d, 1, 0x0d, 0, 2],
    ] {
        let data = version_fixture(3, &root, 0);
        assert!(
            parse_source_with_options(
                &data.as_slice(),
                ParseOptions {
                    encryption: crate::psb::PsbEncryption::None,
                    ..ParseOptions::default()
                }
            )
            .is_err(),
            "accepted {root:x?}"
        );
    }
    let mut data = version_fixture(4, &[1], 0);
    data[40] ^= 1;
    assert!(matches!(
        parse_source(&data.as_slice(), None),
        Err(Error::Corrupt { offset: 40, .. })
    ));
    let mut data = version_fixture(3, &[1], 0);
    data[40] ^= 1;
    let parsed = parse_source(&data.as_slice(), None).unwrap();
    assert_eq!(parsed.header.checksum_valid(), Some(false));

    // Non-sign-extended negative values exercise every compact signed width.
    for width in 1..=8 {
        let mut encoded = vec![4 + width as u8];
        let mut bytes = [0; 8];
        let value = if width == 8 {
            i64::MIN
        } else {
            -(1i64 << (width * 8 - 1))
        };
        BinaryWriter::u64_le(value as u64, &mut bytes);
        encoded.extend_from_slice(&bytes[..width]);
        let data = version_fixture(3, &encoded, 0);
        assert_eq!(
            parse_source(&data.as_slice(), None).unwrap().root.as_i64(),
            Some(value)
        );
    }
}

#[test]
fn string_encoding_is_explicit_and_cancellation_survives_io() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut data = version_fixture(3, &[0x15, 0], 0);
    let start = BinaryReader::u32_le(&data[20..]) as usize;
    data[start..start + 3].copy_from_slice(&[0x82, 0xa0, 0]);
    assert!(parse_source(&data.as_slice(), None).is_err());
    let options = ParseOptions {
        encoding: encoding_rs::SHIFT_JIS,
        ..ParseOptions::default()
    };
    assert_eq!(
        parse_source_with_options(&data.as_slice(), options)
            .unwrap()
            .root
            .as_str(),
        Some("あ")
    );
    let cancelled = AtomicBool::new(true);
    assert!(matches!(
        parse_source_with_options(
            &data.as_slice(),
            ParseOptions {
                cancelled: Some(&cancelled),
                ..options
            }
        ),
        Err(Error::Cancelled)
    ));

    struct Cancelling<'a> {
        bytes: &'a [u8],
        flag: &'a AtomicBool,
    }
    impl ReadAt for Cancelling<'_> {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn read_at(&self, offset: u64, size: usize) -> std::io::Result<std::borrow::Cow<'_, [u8]>> {
            let strings = u64::from(BinaryReader::u32_le(&self.bytes[16..]));
            if offset <= strings && strings < offset + size as u64 {
                self.flag.store(true, Ordering::Relaxed);
            }
            self.bytes.read_at(offset, size)
        }
    }
    cancelled.store(false, Ordering::Relaxed);
    let source = Cancelling {
        bytes: &data,
        flag: &cancelled,
    };
    assert!(matches!(
        parse_source_with_options(
            &source,
            ParseOptions {
                cancelled: Some(&cancelled),
                ..options
            }
        ),
        Err(Error::Cancelled)
    ));
}

#[test]
fn v4_extra_chunks_inside_the_encrypted_body_are_decrypted_only_on_access() {
    use crate::psb::PsbEncryption;
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Guarded {
        data: Vec<u8>,
        extra: u64,
        normal: u64,
        access: Arc<AtomicBool>,
    }
    impl ReadAt for Guarded {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }
        fn read_at(&self, at: u64, size: usize) -> std::io::Result<std::borrow::Cow<'_, [u8]>> {
            let end = at + size as u64;
            if !self.access.load(Ordering::Relaxed) {
                assert!(
                    end <= self.extra || at >= self.extra + 5,
                    "mount read an extra chunk"
                );
                assert!(end <= self.normal, "mount read a normal chunk");
            }
            Ok(std::borrow::Cow::Borrowed(
                &self.data[at as usize..end as usize],
            ))
        }
    }
    for mode in [PsbEncryption::Body, PsbEncryption::Full] {
        let mut data = version_fixture(4, &[0x22, 0], 0);
        let plain = data.clone();
        let normal = u64::from(BinaryReader::u32_le(&data[32..]));
        let extra = u64::from(BinaryReader::u32_le(&data[52..]));
        let boundary = u64::from(BinaryReader::u32_le(&data[24..]));
        assert!(extra < boundary);
        encrypt_fixture(&mut data, mode, 0x1234_5678);
        let access = Arc::new(AtomicBool::new(false));
        let source = Arc::new(Guarded {
            data,
            extra,
            normal,
            access: access.clone(),
        });
        let (psb, source) = parse_shared_source(
            source,
            ParseOptions {
                psb_key: Some(0x1234_5678),
                ..ParseOptions::default()
            },
        )
        .unwrap();
        assert_eq!(psb.encryption, mode);
        access.store(true, Ordering::Relaxed);
        assert_eq!(&*source.read_at(normal, 3).unwrap(), b"res");
        assert_eq!(&*source.read_at(extra, 5).unwrap(), b"extra");
        assert_eq!(&*source.read_at(extra + 2, 2).unwrap(), b"tr");
        assert_eq!(
            &*source.read_at(boundary - 2, 4).unwrap(),
            &plain[boundary as usize - 2..boundary as usize + 2]
        );
    }
}

#[test]
fn clear_header_hints_do_not_force_decryption_and_v1_keeps_all_key_widths() {
    use crate::psb::PsbEncryption;
    let mut data = version_fixture(2, &[2], 0);
    BinaryWriter::u32_le(0, &mut data[8..]);
    BinaryWriter::u16_le(1, &mut data[6..]);
    let parsed = parse_source(&data.as_slice(), Some(123)).unwrap();
    assert_eq!(parsed.header.header_length, 0);
    assert_eq!(parsed.header.flags, 1);
    assert_eq!(parsed.encryption, PsbEncryption::None);
    for width in 1..=4 {
        let mut root = vec![0x21, 0x0d, 1, 0x0d, 0, 0x10 + width];
        root.resize(6 + usize::from(width), 0);
        root.push(2);
        let data = version_fixture(1, &root, 0);
        let parsed = parse_source(&data.as_slice(), None).unwrap();
        assert_eq!(parsed.root.as_object().unwrap()["a"], PsbValue::Bool(true));
    }
}
