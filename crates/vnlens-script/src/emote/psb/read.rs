//! Read-only PSB index loading; resource bodies stay as unrequested ranges.
//! Native PSBObject initialization loads the prefix ending at resource data.
use super::super::mdf;
use super::header::validate_header;
use super::value::ValueParser;
use super::{ParseOptions, Psb, PsbHeader, PsbResource, corrupt};
use std::sync::Arc;
use vnlens_core::{Error, Result};
use vnlens_io::{ArcView, BinaryReader, BinarySourceReader, ReadAt};

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
        return Err(vnlens_io::BinaryIo::unexpected_eof("truncated PSB array payload").into());
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
#[path = "../../../tests/emote/psb/read.rs"]
mod tests;
