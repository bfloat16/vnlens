//! CScript::Load 0x45d030: header words 4..9 describe message/resource/
//! label tables; word 10 is the scene-label base (0x410c90, 0x410ce0).
//! Word 18 points to signed constants resolved at 0x45dc80. Words 20,22,23
//! address call/command/script-call records used by save restoration at
//! 0x45def0 and 0x40d200; the resume address is after the referenced record.
//! Words 16/17 point to auxiliary record headers rather than their payloads.
//! This host does not read those two tables, or word 21's choice index.
//! Their observed integer/address layouts are retained without naming their
//! unverified purpose. Strings use absolute word pointers and CP932 bytes.
use super::spt::{arg, byte_offset, unsigned, word};
use crate::ir::{Arg, ArgName as A, Attribute, Qualifier as Q, Value};
use nvlens_core::Result;
use nvlens_io::BinaryReader;
use std::collections::BTreeSet;

pub(super) fn parse(
    data: &[u8],
    body: &[u8],
    at: usize,
    code: u32,
) -> Result<(Option<Q>, Vec<Arg>)> {
    if at == 0 && code == 0x55550001 {
        return Ok((Some(Q::ScriptMetadata), header(data, body)?));
    }
    if code != 0x55550002 || body.len() < 4 {
        return Ok((
            None,
            vec![arg(
                A::Data,
                at + 12,
                body.len(),
                Value::Bytes(body.to_vec()),
            )],
        ));
    }
    let subtype = word(body, 0)?;
    let mut args = vec![unsigned(A::Type, at + 12, subtype)];
    let start = at + 16;
    let payload = &body[4..];
    for (count_field, offset_field, name, qualifier) in [
        (4, 5, A::Messages, Q::MessageTable),
        (6, 7, A::Resources, Q::ResourceTable),
        (8, 9, A::Labels, Q::LabelTable),
    ] {
        if byte_offset(word(data, offset_field)?)? != start {
            continue;
        }
        let size = byte_offset(word(data, count_field)?)?;
        let mut reader = BinaryReader::new(payload);
        let pointers = reader.read_bytes(size)?;
        let mut fields = Vec::new();
        for (index, bytes) in pointers.as_chunks::<4>().0.iter().enumerate() {
            let value = BinaryReader::u32_le(bytes);
            fields.push(address(
                A::ValueAt(index as u64),
                start + index * 4,
                value,
                name == A::Labels,
            )?);
        }
        args.push(arg(name, start, size, Value::Group(fields)));
        if name != A::Labels {
            args.extend(strings(data, payload, start, size, pointers)?);
        } else {
            append_words(
                &mut args,
                reader.read_bytes(reader.remaining())?,
                start + size,
                1 + size / 4,
            );
        }
        return Ok((Some(qualifier), args));
    }
    if byte_offset(word(data, 18)?)? == start {
        let constants = payload
            .as_chunks::<4>()
            .0
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                arg(
                    A::Constant(index as u64),
                    start + index * 4,
                    4,
                    Value::Integer(i64::from(BinaryReader::u32_le(bytes) as i32)),
                )
            })
            .collect();
        args.push(arg(
            A::Constants,
            start,
            payload.len(),
            Value::Group(constants),
        ));
        return Ok((Some(Q::ConstantTable), args));
    }
    if word(data, 0)? >= 32 {
        for (field, name, qualifier) in [
            (20, A::ReturnTargets, Q::ReturnTable),
            (21, A::ChoiceTargets, Q::ChoiceTable),
            (22, A::CommandTargets, Q::CommandTable),
            (23, A::ScriptCallTargets, Q::ScriptTable),
        ] {
            if byte_offset(word(data, field)?)? != start {
                continue;
            }
            let mut fields = Vec::new();
            for (index, bytes) in payload.as_chunks::<4>().0.iter().enumerate() {
                let value = BinaryReader::u32_le(bytes);
                let position = start + index * 4;
                // Choice IDs are one-based. The compiler leaves slot zero
                // uninterpreted (non-address values occur in real scripts).
                if field == 21 && index == 0 {
                    fields.push(unsigned(A::Unknown(0), position, value));
                } else if field != 21 {
                    let target = byte_offset(value)?;
                    let mut record = BinaryReader::new_at(data, target)?;
                    let size = byte_offset(record.read_u32_le()?)?;
                    let mut record = BinaryReader::new_at(data, target)?;
                    record.read_bytes(size)?;
                    fields.push(arg(
                        A::ValueAt(index as u64),
                        position,
                        4,
                        Value::Group(vec![
                            address(A::Target, position, value, true)?,
                            arg(
                                A::ResolvedTarget,
                                position,
                                0,
                                Value::CodeAddress(record.position() as u64),
                            ),
                        ]),
                    ));
                } else {
                    fields.push(address(A::ValueAt(index as u64), position, value, true)?);
                }
            }
            args.push(arg(name, start, payload.len(), Value::Group(fields)));
            return Ok((Some(qualifier), args));
        }
    }
    for field in [16, 17] {
        if byte_offset(word(data, field)?)? != at {
            continue;
        }
        let mut fields = Vec::new();
        for (index, bytes) in payload.as_chunks::<4>().0.iter().enumerate() {
            let value = BinaryReader::u32_le(bytes);
            let position = start + index * 4;
            fields.push(if field == 17 {
                address(A::ValueAt(index as u64), position, value, true)?
            } else {
                unsigned(A::Unknown(index as u64), position, value)
            });
        }
        args.push(arg(
            if field == 17 { A::Targets } else { A::Metadata },
            start,
            payload.len(),
            Value::Group(fields),
        ));
        return Ok((
            Some(if field == 17 {
                Q::AddressTable
            } else {
                Q::WordTable
            }),
            args,
        ));
    }
    // A subtype alone does not determine the role of repeated 0x44440003
    // records. Unknown layouts keep their native slot numbers and words.
    append_words(&mut args, payload, start, 1);
    Ok((Some(Q::WordTable), args))
}

fn header(data: &[u8], body: &[u8]) -> Result<Vec<Arg>> {
    let mut args = Vec::new();
    let mut index = 3;
    while index < 3 + body.len() / 4 {
        let position = index * 4;
        let name = match index {
            4 => Some(A::Messages),
            6 => Some(A::Resources),
            8 => Some(A::Labels),
            _ => None,
        };
        if let Some(name) = name {
            args.push(arg(
                name,
                position,
                8,
                Value::Group(vec![
                    unsigned(A::Count, position, word(data, index)?),
                    address(A::DataOffset, position + 4, word(data, index + 1)?, false)?,
                ]),
            ));
            index += 2;
        } else if index == 12 {
            args.push(arg(
                A::Signature,
                position,
                16,
                Value::Bytes(
                    BinaryReader::new_at(data, position)?
                        .read_bytes(16)?
                        .to_vec(),
                ),
            ));
            index += 4;
        } else {
            let value = word(data, index)?;
            let pointer_name = match index {
                16 | 17 => Some(A::Unknown((index - 3) as u64)),
                18 => Some(A::Constants),
                20 => Some(A::ReturnTargets),
                21 => Some(A::ChoiceTargets),
                22 => Some(A::CommandTargets),
                23 => Some(A::ScriptCallTargets),
                _ => None,
            };
            if let Some(name) = pointer_name {
                let pointer = address(A::DataOffset, position, value, false)?;
                args.push(arg(name, position, 4, Value::Group(vec![pointer])));
            } else {
                args.push(unsigned(
                    if index == 10 {
                        A::LabelBase
                    } else {
                        A::Unknown((index - 3) as u64)
                    },
                    position,
                    value,
                ));
            }
            index += 1;
        }
    }
    Ok(args)
}

fn strings(
    data: &[u8],
    payload: &[u8],
    start: usize,
    table_size: usize,
    pointers: &[u8],
) -> Result<Vec<Arg>> {
    let pool_start = start + table_size;
    let end = start + payload.len();
    let mut referenced = BTreeSet::new();
    for bytes in pointers.as_chunks::<4>().0 {
        let pointer = byte_offset(BinaryReader::u32_le(bytes))?;
        if (pool_start..end).contains(&pointer) {
            referenced.insert(pointer);
        } else {
            let mut reader = BinaryReader::new_at(data, pointer)?;
            while reader.read_u8()? != 0 {}
        }
    }
    let mut fields = Vec::new();
    let mut cursor = pool_start;
    for (index, pointer) in referenced.into_iter().enumerate() {
        if pointer > cursor {
            fields.push(gap(data, cursor, pointer));
        }
        let mut reader = BinaryReader::new_at(data, pointer)?;
        while reader.read_u8()? != 0 {}
        let text_end = reader.position() - 1;
        let bytes = &data[pointer..text_end];
        let (text, _, errors) = encoding_rs::SHIFT_JIS.decode(bytes);
        let value = if errors {
            Value::Bytes(bytes.to_vec())
        } else {
            Value::Text(text.into_owned())
        };
        fields.push(arg(
            A::StringAt(index as u64),
            pointer,
            reader.position() - pointer,
            Value::Group(vec![
                arg(A::Text, pointer, bytes.len(), value),
                arg(A::Terminator(0), text_end, 1, Value::Unsigned(0)),
            ]),
        ));
        // Aliases and shared suffixes may overlap; do not truncate strings
        // or assume that pointers are sorted in the stored pointer table.
        cursor = cursor.max(reader.position());
    }
    if cursor < end {
        fields.push(gap(data, cursor, end));
    }
    Ok(vec![arg(
        A::StringPool,
        pool_start,
        end - pool_start,
        Value::Group(fields),
    )])
}

fn gap(data: &[u8], start: usize, end: usize) -> Arg {
    let alignment = (4 - start % 4) % 4;
    let name = if end - start <= alignment {
        A::Padding
    } else {
        A::Data
    };
    arg(
        name,
        start,
        end - start,
        Value::Bytes(data[start..end].to_vec()),
    )
}

fn append_words(args: &mut Vec<Arg>, bytes: &[u8], start: usize, ordinal: usize) {
    for (index, bytes) in bytes.as_chunks::<4>().0.iter().enumerate() {
        args.push(unsigned(
            A::Unknown((ordinal + index) as u64),
            start + index * 4,
            BinaryReader::u32_le(bytes),
        ));
    }
}
fn address(name: A, at: usize, word: u32, code: bool) -> Result<Arg> {
    let offset = byte_offset(word)? as u64;
    let mut value = arg(
        name,
        at,
        4,
        if code {
            Value::CodeAddress(offset)
        } else {
            Value::DataAddress(offset)
        },
    );
    value.attributes.push(Attribute {
        name: "word_offset".into(),
        value: u64::from(word),
    });
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;

    fn put(bytes: &mut [u8], index: usize, value: u32) {
        BinaryWriter::u32_le(value, &mut bytes[index * 4..]);
    }
    fn header_bytes() -> Vec<u8> {
        let mut data = vec![0; 128];
        for (index, value) in [(0, 32), (1, 0x66660001), (2, 0x55550001)] {
            put(&mut data, index, value);
        }
        data[48..58].copy_from_slice(b"SPTHEADER0");
        data[58..63].fill(b' ');
        data
    }
    fn record(data: &mut Vec<u8>, subtype: u32, payload: &[u8]) -> usize {
        let start = data.len();
        data.resize(start + 16, 0);
        for (index, value) in [
            (0, 4 + payload.len() as u32 / 4),
            (1, 0x66660001),
            (2, 0x55550002),
            (3, subtype),
        ] {
            put(&mut data[start..], index, value);
        }
        data.extend_from_slice(payload);
        start
    }
    #[test]
    fn string_pools_preserve_aliases_suffixes_non_text_bytes_and_alignment() -> Result<()> {
        let mut data = header_bytes();
        let pool = 128 + 16 + 20;
        let mut payload = vec![0; 20];
        for (index, offset) in [0, 4, 0, 8, 12].into_iter().enumerate() {
            put(&mut payload, index, ((pool + offset) / 4) as u32);
        }
        payload.extend_from_slice(b"abcdefgh\0\xaa\xbb\xcc\x81\0\xdd\xee");
        let start = record(&mut data, 0x44440001, &payload);
        put(&mut data, 6, 5);
        put(&mut data, 7, (start as u32 + 16) / 4);
        let (variant, args) = parse(&data, &data[start + 12..], start, 0x55550002)?;
        assert_eq!(variant, Some(Q::ResourceTable));
        let Value::Group(pointers) = &args[1].value else {
            return Err(nvlens_core::Error::InvalidFormat);
        };
        assert_eq!(pointers.len(), 5);
        assert!(matches!(pointers[0].value,Value::DataAddress(value) if value==pool as u64));
        assert!(matches!(pointers[2].value,Value::DataAddress(value) if value==pool as u64));
        let Value::Group(strings) = &args[2].value else {
            return Err(nvlens_core::Error::InvalidFormat);
        };
        let text: Vec<_> = strings
            .iter()
            .filter_map(|item| match &item.value {
                Value::Group(fields) => Some(&fields[0].value),
                _ => None,
            })
            .collect();
        assert_eq!(text.len(), 4);
        assert!(matches!(text[0],Value::Text(value) if value=="abcdefgh"));
        assert!(matches!(text[1],Value::Text(value) if value=="efgh"));
        assert!(matches!(text[2],Value::Text(value) if value.is_empty()));
        assert!(matches!(text[3],Value::Bytes(value) if value==&[0x81]));
        assert!(strings.iter().any(|arg| arg.name == A::Padding
            && matches!(&arg.value,Value::Bytes(bytes) if bytes==&[0xaa,0xbb,0xcc])));
        let at = pool + 13;
        data[at] = 0xff;
        assert!(
            matches!(parse(&data,&data[start+12..],start,0x55550002),Err(nvlens_core::Error::Io(error)) if error.kind()==std::io::ErrorKind::UnexpectedEof)
        );
        Ok(())
    }
    #[test]
    fn signed_constants_and_empty_tables_use_structural_variants() -> Result<()> {
        let mut data = header_bytes();
        let mut payload = vec![0; 8];
        put(&mut payload, 0, u32::MAX);
        put(&mut payload, 1, 0x80000000);
        let start = record(&mut data, 0x44440004, &payload);
        put(&mut data, 18, (start as u32 + 16) / 4);
        let (variant, args) = parse(&data, &data[start + 12..], start, 0x55550002)?;
        assert_eq!(variant, Some(Q::ConstantTable));
        let Value::Group(constants) = &args[1].value else {
            return Err(nvlens_core::Error::InvalidFormat);
        };
        assert!(matches!(constants[0].value, Value::Integer(-1)));
        assert!(matches!(constants[1].value, Value::Integer(-2147483648)));
        let start = record(&mut data, 0x44440008, &[]);
        put(&mut data, 23, (start as u32 + 16) / 4);
        let (variant, args) = parse(&data, &data[start + 12..], start, 0x55550002)?;
        assert_eq!(variant, Some(Q::ScriptTable));
        assert!(matches!(&args[1].value,Value::Group(values) if values.is_empty()));
        Ok(())
    }
    #[test]
    fn header_signature_table_roles_and_unverified_words_keep_source_positions() -> Result<()> {
        let mut data = header_bytes();
        put(&mut data, 10, 7);
        put(&mut data, 19, 123);
        put(&mut data, 20, 36);
        let (variant, args) = parse(&data, &data[12..], 0, 0x55550001)?;
        assert_eq!(variant, Some(Q::ScriptMetadata));
        assert!(
            args.iter()
                .any(|arg| arg.name == A::LabelBase && matches!(arg.value, Value::Unsigned(7)))
        );
        assert!(args.iter().any(|arg| arg.name == A::Unknown(16)
            && arg.span.offset == 76
            && matches!(arg.value, Value::Unsigned(123))));
        let signature = args
            .iter()
            .find(|arg| arg.name == A::Signature)
            .ok_or(nvlens_core::Error::InvalidFormat)?;
        assert_eq!(signature.span.size, 16);
        assert!(matches!(&signature.value,Value::Bytes(bytes) if bytes==&data[48..64]));
        Ok(())
    }
}
