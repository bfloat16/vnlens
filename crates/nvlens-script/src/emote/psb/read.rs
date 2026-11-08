//! Read-only PSB index loading; resource bodies stay as unrequested ranges.
//! Native PSBObject initialization loads the prefix ending at resource data.
use super::super::mdf;
use super::header::validate_header;
use super::value::ValueParser;
use super::{ParseOptions, Psb, PsbHeader, PsbResource, corrupt};
use nvlens_core::{Error, Result};
use nvlens_io::{ArcView, BinaryReader, BinarySourceReader, ReadAt};
use std::sync::Arc;

/// Opens an index source, leaving resource bodies unrequested.
pub fn open_source(view: Arc<ArcView>, options: ParseOptions<'_>) -> Result<Arc<dyn ReadAt>> {
    if view.len() >= 4 && mdf::is_mdf(view.slice(0, 4)?) {
        return Ok(Arc::new(super::super::mdf_source::MdfSource::new(
            view,
            options.mdf_key,
        )?));
    }
    Ok(view)
}

/// Parses the index of a mapped or transformed PSB source.
pub fn parse_source(data: &dyn ReadAt, psb_key: Option<u32>) -> Result<Psb> {
    let header = PsbHeader::read(data, psb_key)?;
    if header.is_header_encrypted() && psb_key.is_none() {
        return Err(Error::UnknownScheme(Some("psb header key".to_string())));
    }
    validate_header(&header, data.len())?;

    let string_offsets = read_array_at(data, header.offset_strings)?;
    let strings = load_strings(data, &header, &string_offsets)?;
    let names = load_names(data, &header)?;

    let chunk_offsets = read_array_at(data, header.offset_chunk_offsets)?;
    let chunk_lengths = read_array_at(data, header.offset_chunk_lengths)?;
    let resources = load_resources(
        data,
        &chunk_offsets,
        &chunk_lengths,
        header.offset_chunk_data,
        false,
    )?;

    let extra_resources = if header.version >= 4 {
        let offsets = read_array_at(
            data,
            header
                .offset_extra_chunk_offsets
                .ok_or_else(|| corrupt(0, "PSB v4 missing extra chunk offsets"))?,
        )?;
        let lengths = read_array_at(
            data,
            header
                .offset_extra_chunk_lengths
                .ok_or_else(|| corrupt(0, "PSB v4 missing extra chunk lengths"))?,
        )?;
        load_resources(
            data,
            &offsets,
            &lengths,
            header
                .offset_extra_chunk_data
                .ok_or_else(|| corrupt(0, "PSB v4 missing extra chunk data"))?,
            true,
        )?
    } else {
        Vec::new()
    };

    let mut parser = ValueParser {
        data,
        header: &header,
        names: &names,
        strings: &strings,
        resource_count: resources.len(),
        extra_resource_count: extra_resources.len(),
    };
    let mut reader = reader_at(data, header.offset_entries)?;
    let root = parser.read_value(&mut reader)?;

    Ok(Psb {
        data_len: data.len(),
        names,
        strings,
        resources,
        extra_resources,
        root,
    })
}

fn load_names(data: &dyn ReadAt, header: &PsbHeader) -> Result<Vec<String>> {
    if header.version == 1 {
        let name_indexes = read_array_at(data, header.header_length)?;
        let mut names = Vec::with_capacity(name_indexes.len());
        for index in name_indexes {
            let pos = u64::from(header.offset_names)
                .checked_add(u64::from(index))
                .ok_or_else(|| {
                    corrupt(u64::from(header.offset_names), "PSB name offset overflow")
                })?;
            names.push(read_cstring_at(data, pos)?);
        }
        return Ok(names);
    }

    let mut reader = reader_at(data, header.offset_names)?;
    let charset = read_array_with_tag(&mut reader)?;
    let names_data = read_array_with_tag(&mut reader)?;
    let name_indexes = read_array_with_tag(&mut reader)?;
    let mut names = Vec::with_capacity(name_indexes.len());

    for index in name_indexes {
        let mut bytes = Vec::new();
        let mut chr = *names_data.get(usize_from_u32(index)?).ok_or_else(|| {
            corrupt(
                u64::from(header.offset_names),
                "PSB name trie index out of range",
            )
        })?;
        let mut steps = 0usize;
        while chr != 0 {
            if steps > names_data.len() {
                return Err(corrupt(
                    u64::from(header.offset_names),
                    "PSB name trie cycle detected",
                ));
            }
            let code = *names_data.get(usize_from_u32(chr)?).ok_or_else(|| {
                corrupt(
                    u64::from(header.offset_names),
                    "PSB name trie code out of range",
                )
            })?;
            let delta = *charset.get(usize_from_u32(code)?).ok_or_else(|| {
                corrupt(
                    u64::from(header.offset_names),
                    "PSB charset index out of range",
                )
            })?;
            let real = chr.checked_sub(delta).ok_or_else(|| {
                corrupt(u64::from(header.offset_names), "PSB name byte underflow")
            })?;
            let byte = u8::try_from(real).map_err(|_| {
                corrupt(u64::from(header.offset_names), "PSB name byte out of range")
            })?;
            bytes.push(byte);
            chr = code;
            steps += 1;
        }
        bytes.reverse();
        let name = String::from_utf8(bytes)
            .map_err(|_| corrupt(u64::from(header.offset_names), "PSB name is not UTF-8"))?;
        names.push(name);
    }

    Ok(names)
}

fn load_strings(
    data: &dyn ReadAt,
    header: &PsbHeader,
    string_offsets: &[u32],
) -> Result<Vec<String>> {
    let mut strings = Vec::with_capacity(string_offsets.len());
    for offset in string_offsets {
        let pos = u64::from(header.offset_strings_data)
            .checked_add(u64::from(*offset))
            .ok_or_else(|| {
                corrupt(
                    u64::from(header.offset_strings_data),
                    "PSB string offset overflow",
                )
            })?;
        strings.push(read_cstring_at(data, pos)?);
    }
    Ok(strings)
}

fn load_resources(
    data: &dyn ReadAt,
    offsets: &[u32],
    lengths: &[u32],
    data_offset: u32,
    is_extra: bool,
) -> Result<Vec<PsbResource>> {
    if offsets.len() != lengths.len() {
        return Err(corrupt(
            u64::from(data_offset),
            "PSB resource offset/length count mismatch",
        ));
    }
    let mut resources = Vec::with_capacity(offsets.len());
    for (index, (&offset, &length)) in offsets.iter().zip(lengths).enumerate() {
        let start = u64::from(data_offset)
            .checked_add(u64::from(offset))
            .ok_or_else(|| corrupt(u64::from(data_offset), "PSB resource offset overflow"))?;
        let end = start
            .checked_add(u64::from(length))
            .ok_or_else(|| corrupt(start, "PSB resource length overflow"))?;
        if end > data.len() {
            return Err(corrupt(start, "PSB resource is out of range"));
        }
        resources.push(PsbResource {
            index: u32::try_from(index)
                .map_err(|_| corrupt(start, "PSB resource index does not fit u32"))?,
            is_extra,
            offset: start,
            size: u64::from(length),
        });
    }
    Ok(resources)
}

fn read_array_at(data: &dyn ReadAt, offset: u32) -> Result<Vec<u32>> {
    let mut reader = reader_at(data, offset)?;
    read_array_with_tag(&mut reader)
}

pub(super) fn read_array_with_tag(reader: &mut BinarySourceReader<'_>) -> Result<Vec<u32>> {
    let tag_offset = reader.position();
    let tag = reader.read_u8()?;
    if !(0x0D..=0x14).contains(&tag) {
        return Err(corrupt(tag_offset as u64, "PSB array tag is invalid"));
    }
    read_array_payload(reader, usize::from(tag - 0x0C))
}

pub(super) fn read_array_payload(
    reader: &mut BinarySourceReader<'_>,
    count_width: usize,
) -> Result<Vec<u32>> {
    let count = reader.read_compact_u64_le(count_width)?;
    let count_usize = usize::try_from(count)
        .map_err(|_| corrupt(reader.position() as u64, "PSB array too large"))?;
    let entry_tag_offset = reader.position();
    let entry_tag = reader.read_u8()?;
    if entry_tag < 0x0C {
        return Err(corrupt(
            entry_tag_offset as u64,
            "PSB array entry width tag is invalid",
        ));
    }
    let entry_width = usize::from(entry_tag - 0x0C);
    if entry_width == 0 || entry_width > 8 {
        return Err(corrupt(
            entry_tag_offset as u64,
            "PSB array entry width is unsupported",
        ));
    }

    let byte_len = count_usize
        .checked_mul(entry_width)
        .ok_or_else(|| corrupt(reader.position() as u64, "PSB array byte length overflow"))?;
    if byte_len as u64 > reader.remaining() {
        return Err(nvlens_io::BinaryIo::unexpected_eof("truncated PSB array payload").into());
    }
    let mut values = Vec::with_capacity(count_usize);
    for _ in 0..count_usize {
        let value = reader.read_compact_u64_le(entry_width)?;
        values.push(
            u32::try_from(value).map_err(|_| {
                corrupt(reader.position() as u64, "PSB array value does not fit u32")
            })?,
        );
    }
    Ok(values)
}

pub(super) fn read_index(reader: &mut BinarySourceReader<'_>, width: usize) -> Result<u32> {
    let value = reader.read_compact_u64_le(width)?;
    u32::try_from(value)
        .map_err(|_| corrupt(reader.position() as u64, "PSB index does not fit u32"))
}

pub(super) fn read_integer(reader: &mut BinarySourceReader<'_>, width: usize) -> Result<i64> {
    if width == 0 {
        return Ok(0);
    }
    if width > 8 {
        return Err(corrupt(
            reader.position() as u64,
            "PSB integer width exceeds 8",
        ));
    }
    Ok(BinaryReader::compact_i64_le(&reader.read_bytes(width)?)?)
}

fn read_cstring_at(data: &dyn ReadAt, offset: u64) -> Result<String> {
    let start =
        usize::try_from(offset).map_err(|_| corrupt(offset, "string offset does not fit usize"))?;
    let mut reader = BinarySourceReader::new_at(data, start)?;
    let mut bytes = Vec::new();
    loop {
        let byte = reader.read_u8()?;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
    }
    String::from_utf8(bytes).map_err(|_| corrupt(offset, "string is not UTF-8"))
}

pub(super) fn reader_at(data: &dyn ReadAt, offset: u32) -> Result<BinarySourceReader<'_>> {
    BinarySourceReader::new_at(data, usize_from_u32(offset)?).map_err(Error::from)
}

pub(super) fn usize_from_u32(value: u32) -> Result<usize> {
    usize::try_from(value).map_err(|_| corrupt(u64::from(value), "value does not fit usize"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::{PSB_MAGIC, PsbNumber, PsbValue};
    use nvlens_io::{BinaryReader, BinaryWriter};
    use std::collections::BTreeMap;

    use super::*;

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
            fn read_at(
                &self,
                offset: u64,
                size: usize,
            ) -> std::io::Result<std::borrow::Cow<'_, [u8]>> {
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
    fn parses_minimal_mdf_wrapped_psb_fixture() {
        let psb = minimal_psb_fixture();
        let mdf = super::mdf::encode_fixture(&psb);
        let decoded = super::mdf::decode(&mdf, None).unwrap();
        let parsed = parse_source(&decoded.as_slice(), None).unwrap();
        assert_eq!(parsed.names, vec!["abcde"]);
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
}
