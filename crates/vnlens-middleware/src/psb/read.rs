//! Read-only PSB index loading; resource bodies stay as unrequested ranges.
//! Native PSBObject initialization loads the prefix ending at resource data.
use super::source::{IndexSource, PsbSource};
use super::value::ValueParser;
use super::{ParseOptions, Psb, PsbEncryption, PsbHeader, PsbResource, check_cancelled, corrupt};
use crate::mdf;
use std::sync::Arc;
use vnlens_core::{Error, Result};
use vnlens_io::{BinaryReader, BinarySourceReader, ReadAt};

/// Opens an index source, leaving resource bodies unrequested.
pub fn open_source(view: Arc<dyn ReadAt>, options: ParseOptions<'_>) -> Result<Arc<dyn ReadAt>> {
    if view.len() >= 4 && mdf::is_mdf(&view.read_at(0, 4)?) {
        return Ok(Arc::new(crate::mdf_source::MdfSource::new(
            view,
            options.mdf_key,
        )?));
    }
    Ok(view)
}

/// Parses the index of a mapped or transformed PSB source.
pub fn parse_source(data: &dyn ReadAt, psb_key: Option<u32>) -> Result<Psb> {
    parse_source_with_options(
        data,
        ParseOptions {
            psb_key,
            ..ParseOptions::default()
        },
    )
}

/// Parses PSB v1-v4 metadata with explicit encryption, text encoding and
/// cancellation. Resource payloads remain source ranges. Invalid indexes
/// return `Corrupt`; short reads retain `UnexpectedEof` through `Io`.
pub fn parse_source_with_options(data: &dyn ReadAt, options: ParseOptions<'_>) -> Result<Psb> {
    check_cancelled(options)?;
    let result = parse_index(data, options);
    check_cancelled(options)?;
    result
}

fn parse_index(data: &dyn ReadAt, options: ParseOptions<'_>) -> Result<Psb> {
    let (source, header, encryption) = PsbSource::new(data, options)?;
    read_index_tree(&source, header, encryption, options)
}

/// Parses an owned source and retains its body-decryption view for later
/// resource access. In v4 extra chunks may precede the regular chunk tables,
/// inside the encrypted range. Neither path materializes those chunks here.
/// Cancellation applies to parsing; later reads are controlled by the host.
pub fn parse_shared_source(
    data: Arc<dyn ReadAt>,
    options: ParseOptions<'_>,
) -> Result<(Psb, Arc<dyn ReadAt>)> {
    check_cancelled(options)?;
    let (source, header, encryption) = PsbSource::new(&*data, options)?;
    let parsed = read_index_tree(&source, header, encryption, options);
    check_cancelled(options)?;
    Ok((parsed?, Arc::new(source.into_shared(Arc::clone(&data)))))
}

fn read_index_tree(
    data: &dyn ReadAt,
    header: PsbHeader,
    encryption: PsbEncryption,
    options: ParseOptions<'_>,
) -> Result<Psb> {
    let index = IndexSource::new(data, &header, options.cancelled);
    let data: &dyn ReadAt = &index;
    let names = load_names(data, &header, options)?;
    let string_offsets = read_array_at(data, header.offset_strings)?;
    let strings = load_strings(data, &header, &string_offsets, options)?;

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
        nodes: Default::default(),
        options,
    };
    let mut reader = reader_at(data, header.offset_entries)?;
    let root = parser.read_value(&mut reader)?;
    let nodes = parser.nodes;
    check_cancelled(options)?;

    Ok(Psb {
        shell: None,
        header,
        encryption,
        nodes,
        data_len: data.len(),
        names,
        strings,
        resources,
        extra_resources,
        root,
    })
}

fn load_names(
    data: &dyn ReadAt,
    header: &PsbHeader,
    options: ParseOptions<'_>,
) -> Result<Vec<String>> {
    if header.version == 1 {
        let name_indexes = read_array_at(data, header.header_length)?;
        let mut names = Vec::with_capacity(name_indexes.len());
        for index in name_indexes {
            check_cancelled(options)?;
            let pos = u64::from(header.offset_names)
                .checked_add(index)
                .ok_or_else(|| {
                    corrupt(u64::from(header.offset_names), "PSB name offset overflow")
                })?;
            names.push(read_cstring_at(data, pos, options)?);
        }
        return Ok(names);
    }

    let mut reader = reader_at(data, header.offset_names)?;
    let charset = read_array_with_tag(&mut reader)?;
    let names_data = read_array_with_tag(&mut reader)?;
    let name_indexes = read_array_with_tag(&mut reader)?;
    let mut names = Vec::with_capacity(name_indexes.len());

    for index in name_indexes {
        check_cancelled(options)?;
        let mut bytes = Vec::new();
        let mut chr = *names_data.get(usize_from_u64(index)?).ok_or_else(|| {
            corrupt(
                u64::from(header.offset_names),
                "PSB name trie index out of range",
            )
        })?;
        let mut steps = 0usize;
        while chr != 0 {
            check_cancelled(options)?;
            if steps > names_data.len() {
                return Err(corrupt(
                    u64::from(header.offset_names),
                    "PSB name trie cycle detected",
                ));
            }
            let code = *names_data.get(usize_from_u64(chr)?).ok_or_else(|| {
                corrupt(
                    u64::from(header.offset_names),
                    "PSB name trie code out of range",
                )
            })?;
            let delta = *charset.get(usize_from_u64(code)?).ok_or_else(|| {
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
    string_offsets: &[u64],
    options: ParseOptions<'_>,
) -> Result<Vec<String>> {
    let mut strings = Vec::with_capacity(string_offsets.len());
    for offset in string_offsets {
        check_cancelled(options)?;
        let pos = u64::from(header.offset_strings_data)
            .checked_add(*offset)
            .ok_or_else(|| {
                corrupt(
                    u64::from(header.offset_strings_data),
                    "PSB string offset overflow",
                )
            })?;
        strings.push(read_cstring_at(data, pos, options)?);
    }
    Ok(strings)
}

fn load_resources(
    data: &dyn ReadAt,
    offsets: &[u64],
    lengths: &[u64],
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
            .checked_add(offset)
            .ok_or_else(|| corrupt(u64::from(data_offset), "PSB resource offset overflow"))?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| corrupt(start, "PSB resource length overflow"))?;
        if end > data.len() {
            return Err(corrupt(start, "PSB resource is out of range"));
        }
        resources.push(PsbResource {
            index: u32::try_from(index)
                .map_err(|_| corrupt(start, "PSB resource index does not fit u32"))?,
            is_extra,
            offset: start,
            size: length,
        });
    }
    Ok(resources)
}

fn read_array_at(data: &dyn ReadAt, offset: u32) -> Result<Vec<u64>> {
    let mut reader = reader_at(data, offset)?;
    read_array_with_tag(&mut reader)
}

pub(super) fn read_array_with_tag(reader: &mut BinarySourceReader<'_>) -> Result<Vec<u64>> {
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
) -> Result<Vec<u64>> {
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
    while values.len() < count_usize {
        let count = (count_usize - values.len()).min(65536 / entry_width);
        let bytes = reader.read_bytes(count * entry_width)?;
        for bytes in bytes.chunks_exact(entry_width) {
            values.push(BinaryReader::compact_u64_le(bytes)?);
        }
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

fn read_cstring_at(data: &dyn ReadAt, offset: u64, options: ParseOptions<'_>) -> Result<String> {
    let start =
        usize::try_from(offset).map_err(|_| corrupt(offset, "string offset does not fit usize"))?;
    let mut reader = BinarySourceReader::new_at(data, start)?;
    let mut bytes = Vec::new();
    loop {
        check_cancelled(options)?;
        let byte = reader.read_u8()?;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
    }
    options
        .encoding
        .decode_without_bom_handling_and_without_replacement(&bytes)
        .map(|text| text.into_owned())
        .ok_or_else(|| {
            corrupt(
                offset,
                format!("PSB string is not valid {}", options.encoding.name()),
            )
        })
}

pub(super) fn reader_at(data: &dyn ReadAt, offset: u32) -> Result<BinarySourceReader<'_>> {
    BinarySourceReader::new_at(data, usize_from_u32(offset)?).map_err(Error::from)
}

pub(super) fn usize_from_u32(value: u32) -> Result<usize> {
    usize::try_from(value).map_err(|_| corrupt(u64::from(value), "value does not fit usize"))
}

pub(super) fn usize_from_u64(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| corrupt(value, "PSB index does not fit usize"))
}

#[cfg(test)]
#[path = "../../tests/psb/read.rs"]
pub(super) mod tests;
