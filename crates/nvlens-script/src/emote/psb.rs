//! Read-only PSB metadata parser; resources remain source ranges.
//!
//! PSBObject initialization at 0x1000BF30 loads the prefix ending at the
//! resource-data offset. Resource access at 0x1000C6C0 creates a stream window
//! from the offset and length arrays. Integer decoding at 0x1000AFA0 and
//! 0x1000B020 sign-extends the highest encoded byte; boolean tag 2 is true.

use std::collections::BTreeMap;
use std::sync::Arc;

use nvlens_core::{Error, Result};
use nvlens_crypto::cipher::psb_stream::PsbStream;
use nvlens_io::{ArcView, BinaryReader, BinarySourceReader, ReadAt};

use super::mdf::{self, MdfKey};

const PSB_MAGIC: &[u8; 4] = b"PSB\0";

/// Parsed PSB file.
#[derive(Clone, Debug)]
pub struct Psb {
    /// Size of the decoded PSB backing stream, before materializing its tree.
    pub data_len: u64,
    pub header: PsbHeader,
    pub names: Vec<String>,
    pub strings: Vec<String>,
    pub resources: Vec<PsbResource>,
    pub extra_resources: Vec<PsbResource>,
    pub root: PsbValue,
}

/// PSB file header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PsbHeader {
    pub version: u16,
    pub header_encrypt: u16,
    pub header_length: u32,
    pub offset_names: u32,
    pub offset_strings: u32,
    pub offset_strings_data: u32,
    pub offset_chunk_offsets: u32,
    pub offset_chunk_lengths: u32,
    pub offset_chunk_data: u32,
    pub offset_entries: u32,
    pub checksum: Option<u32>,
    pub offset_extra_chunk_offsets: Option<u32>,
    pub offset_extra_chunk_lengths: Option<u32>,
    pub offset_extra_chunk_data: Option<u32>,
}

impl PsbHeader {
    /// FreeMote-compatible heuristic for encrypted headers.
    #[must_use]
    pub fn is_header_encrypted(&self) -> bool {
        self.header_length > 0x200
            || self.offset_names == 0
            || (self.version > 1
                && self.header_length != self.offset_names
                && self.header_length != 0)
    }
}

/// A resource chunk referenced from the PSB object tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PsbResource {
    pub index: u32,
    pub is_extra: bool,
    /// Absolute offset in the decoded PSB byte stream.
    pub offset: u64,
    pub size: u64,
}

/// PSB object tree value.
#[derive(Clone, Debug, PartialEq)]
pub enum PsbValue {
    Null,
    Bool(bool),
    Number(PsbNumber),
    Array(Vec<u32>),
    String { index: u32, value: String },
    Resource { index: u32, is_extra: bool },
    List(Vec<PsbValue>),
    Object(BTreeMap<String, PsbValue>),
}

// Drain nested containers iteratively so a valid deep tree also drops safely.
impl Drop for PsbValue {
    fn drop(&mut self) {
        fn drain(value: &mut PsbValue, pending: &mut Vec<PsbValue>) {
            match value {
                PsbValue::List(items) => pending.append(items),
                PsbValue::Object(items) => pending.extend(std::mem::take(items).into_values()),
                _ => {}
            }
        }
        let mut pending = Vec::new();
        drain(self, &mut pending);
        while let Some(mut value) = pending.pop() {
            drain(&mut value, &mut pending);
        }
    }
}

/// PSB numeric value.
#[derive(Clone, Debug, PartialEq)]
pub enum PsbNumber {
    Integer(i64),
    Float(f32),
    Double(f64),
}

impl PsbNumber {
    /// Returns this value as a signed integer when it is integral.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            Self::Float(_) | Self::Double(_) => None,
        }
    }
}

impl PsbValue {
    /// Returns this value as an object map.
    #[must_use]
    pub fn as_object(&self) -> Option<&BTreeMap<String, PsbValue>> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }

    /// Returns this value as a list.
    #[must_use]
    pub fn as_list(&self) -> Option<&[PsbValue]> {
        match self {
            Self::List(value) => Some(value),
            _ => None,
        }
    }

    /// Returns this value as a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String { value, .. } => Some(value),
            _ => None,
        }
    }

    /// Returns this value as an integral number.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(value) => value.as_i64(),
            _ => None,
        }
    }
}

/// Parser options.
#[derive(Clone, Copy, Default)]
pub struct ParseOptions<'a> {
    pub psb_key: Option<u32>,
    pub mdf_key: Option<MdfKey<'a>>,
}

impl std::fmt::Debug for ParseOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParseOptions").finish_non_exhaustive()
    }
}

/// Archive-info index style.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveInfoKind {
    FileInfo,
    UmdRoot,
}

/// One entry declared by an archive-info PSB.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveInfoEntry {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

/// Extracts archive-info entries from a parsed PSB.
///
/// # Errors
///
/// Returns `InvalidFormat` when the PSB is not an archive-info object, and
/// corrupt-data errors for malformed range lists.
pub fn archive_info_entries(psb: &Psb) -> Result<(ArchiveInfoKind, Vec<ArchiveInfoEntry>)> {
    let root = psb.root.as_object().ok_or(Error::InvalidFormat)?;
    let (kind, key) = if root.contains_key("umd_root") {
        (ArchiveInfoKind::UmdRoot, "umd_root")
    } else if root.contains_key("file_info") {
        (ArchiveInfoKind::FileInfo, "file_info")
    } else {
        return Err(Error::InvalidFormat);
    };

    let table = root
        .get(key)
        .and_then(PsbValue::as_object)
        .ok_or_else(|| corrupt(0, "archive-info root is not an object"))?;
    let mut entries = Vec::with_capacity(table.len());
    for (name, range) in table {
        let range = range
            .as_list()
            .ok_or_else(|| corrupt(0, "archive-info range is not a list"))?;
        let (offset, size) = archive_info_range(range, kind)?;
        entries.push(ArchiveInfoEntry {
            name: name.clone(),
            offset,
            size,
        });
    }
    Ok((kind, entries))
}

/// Returns the archive-info suffix, usually from `expire_suffix_list[0]`.
#[must_use]
pub fn archive_info_suffix(psb: &Psb) -> Option<&str> {
    let root = psb.root.as_object()?;
    let suffixes = root.get("expire_suffix_list")?.as_list()?;
    suffixes.first()?.as_str()
}

/// Returns likely MDF key filenames for an archive entry.
#[must_use]
pub fn archive_info_possible_file_names(
    name: &str,
    suffix: &str,
    keep_directory: bool,
) -> Vec<String> {
    let mut results = Vec::new();
    collect_possible_file_names(name, suffix, keep_directory, &mut results);
    results.dedup();
    results
}

/// Opens an index source, leaving resource bodies unrequested.
pub fn open_source(view: Arc<ArcView>, options: ParseOptions<'_>) -> Result<Arc<dyn ReadAt>> {
    if view.len() >= 4 && mdf::is_mdf(view.slice(0, 4)?) {
        return Ok(Arc::new(super::mdf_source::MdfSource::new(
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
        header,
        names,
        strings,
        resources,
        extra_resources,
        root,
    })
}

impl PsbHeader {
    fn read(data: &dyn ReadAt, psb_key: Option<u32>) -> Result<Self> {
        if data.len() < 4 || data.read_at(0, 4)?.as_ref() != PSB_MAGIC {
            return Err(Error::InvalidFormat);
        }
        let mut reader = BinarySourceReader::new(data);
        let signature = reader.read_bytes(4)?;
        if signature.as_ref() != PSB_MAGIC {
            return Err(Error::InvalidFormat);
        }
        let version = reader.read_u16_le()?;
        let header_encrypt = reader.read_u16_le()?;
        if !(1..=4).contains(&version) {
            return Err(Error::Unsupported(format!("PSB version {version}")));
        }

        if let Some(key) = psb_key {
            let mut stream = PsbStream::new(key);
            let header_length = read_encrypted_u32(&mut reader, &mut stream)?;
            let offset_names = read_encrypted_u32(&mut reader, &mut stream)?;
            let offset_strings = read_encrypted_u32(&mut reader, &mut stream)?;
            let offset_strings_data = read_encrypted_u32(&mut reader, &mut stream)?;
            let offset_chunk_offsets = read_encrypted_u32(&mut reader, &mut stream)?;
            let offset_chunk_lengths = read_encrypted_u32(&mut reader, &mut stream)?;
            let offset_chunk_data = read_encrypted_u32(&mut reader, &mut stream)?;
            let offset_entries = read_encrypted_u32(&mut reader, &mut stream)?;
            let checksum = if version > 2 {
                Some(read_encrypted_u32(&mut reader, &mut stream)?)
            } else {
                None
            };
            let (offset_extra_chunk_offsets, offset_extra_chunk_lengths, offset_extra_chunk_data) =
                if version > 3 {
                    (
                        Some(read_encrypted_u32(&mut reader, &mut stream)?),
                        Some(read_encrypted_u32(&mut reader, &mut stream)?),
                        Some(read_encrypted_u32(&mut reader, &mut stream)?),
                    )
                } else {
                    (None, None, None)
                };
            return Ok(Self {
                version,
                header_encrypt,
                header_length,
                offset_names,
                offset_strings,
                offset_strings_data,
                offset_chunk_offsets,
                offset_chunk_lengths,
                offset_chunk_data,
                offset_entries,
                checksum,
                offset_extra_chunk_offsets,
                offset_extra_chunk_lengths,
                offset_extra_chunk_data,
            });
        }

        let header_length = reader.read_u32_le()?;
        let offset_names = reader.read_u32_le()?;
        let offset_strings = reader.read_u32_le()?;
        let offset_strings_data = reader.read_u32_le()?;
        let offset_chunk_offsets = reader.read_u32_le()?;
        let offset_chunk_lengths = reader.read_u32_le()?;
        let offset_chunk_data = reader.read_u32_le()?;
        let offset_entries = reader.read_u32_le()?;
        let checksum = if version > 2 {
            Some(reader.read_u32_le()?)
        } else {
            None
        };
        let (offset_extra_chunk_offsets, offset_extra_chunk_lengths, offset_extra_chunk_data) =
            if version > 3 {
                (
                    Some(reader.read_u32_le()?),
                    Some(reader.read_u32_le()?),
                    Some(reader.read_u32_le()?),
                )
            } else {
                (None, None, None)
            };

        Ok(Self {
            version,
            header_encrypt,
            header_length,
            offset_names,
            offset_strings,
            offset_strings_data,
            offset_chunk_offsets,
            offset_chunk_lengths,
            offset_chunk_data,
            offset_entries,
            checksum,
            offset_extra_chunk_offsets,
            offset_extra_chunk_lengths,
            offset_extra_chunk_data,
        })
    }
}

struct ValueParser<'a> {
    data: &'a dyn ReadAt,
    header: &'a PsbHeader,
    names: &'a [String],
    strings: &'a [String],
    resource_count: usize,
    extra_resource_count: usize,
}

enum ValueTask {
    Read(usize),
    List(usize),
    Object(Vec<String>),
}

impl ValueParser<'_> {
    fn read_value(&mut self, reader: &mut BinarySourceReader<'_>) -> Result<PsbValue> {
        let mut tasks = vec![ValueTask::Read(reader.position())];
        let mut values = Vec::new();
        while let Some(task) = tasks.pop() {
            match task {
                ValueTask::List(count) => {
                    let start = values
                        .len()
                        .checked_sub(count)
                        .ok_or_else(|| corrupt(0, "incomplete PSB list"))?;
                    let children = values.split_off(start);
                    values.push(PsbValue::List(children));
                    continue;
                }
                ValueTask::Object(names) => {
                    let start = values
                        .len()
                        .checked_sub(names.len())
                        .ok_or_else(|| corrupt(0, "incomplete PSB object"))?;
                    let children = values.split_off(start);
                    let mut object = BTreeMap::new();
                    for (name, child) in names.into_iter().zip(children) {
                        if object.insert(name, child).is_some() {
                            return Err(corrupt(0, "duplicate PSB object key"));
                        }
                    }
                    values.push(PsbValue::Object(object));
                    continue;
                }
                ValueTask::Read(offset) => {
                    let mut reader = BinarySourceReader::new_at(self.data, offset)?;
                    let tag = reader.read_u8()?;
                    let value = match tag {
                        0x00 | 0x01 => PsbValue::Null,
                        0x02 => PsbValue::Bool(true),
                        0x03 => PsbValue::Bool(false),
                        0x04 => PsbValue::Number(PsbNumber::Integer(0)),
                        0x05..=0x0C => PsbValue::Number(PsbNumber::Integer(read_integer(
                            &mut reader,
                            usize::from(tag - 4),
                        )?)),
                        0x0D..=0x14 => PsbValue::Array(read_array_payload(
                            &mut reader,
                            usize::from(tag - 0x0C),
                        )?),
                        0x15..=0x18 => {
                            let index = read_index(&mut reader, usize::from(tag - 0x14))?;
                            let value = self
                                .strings
                                .get(usize_from_u32(index)?)
                                .ok_or_else(|| {
                                    corrupt(offset as u64, "PSB string index out of range")
                                })?
                                .clone();
                            PsbValue::String { index, value }
                        }
                        0x19..=0x1C | 0x22..=0x25 => {
                            let is_extra = tag >= 0x22;
                            let width = usize::from(tag - if is_extra { 0x21 } else { 0x18 });
                            let index = read_index(&mut reader, width)?;
                            let count = if is_extra {
                                self.extra_resource_count
                            } else {
                                self.resource_count
                            };
                            if usize_from_u32(index)? >= count {
                                return Err(corrupt(
                                    offset as u64,
                                    "PSB resource index out of range",
                                ));
                            }
                            PsbValue::Resource { index, is_extra }
                        }
                        0x1D => PsbValue::Number(PsbNumber::Float(0.0)),
                        0x1E => PsbValue::Number(PsbNumber::Float(f32::from_bits(
                            reader.read_u32_le()?,
                        ))),
                        0x1F => PsbValue::Number(PsbNumber::Double(f64::from_bits(
                            reader.read_u64_le()?,
                        ))),
                        0x20 | 0x21 => {
                            let name_indexes = if tag == 0x21 && self.header.version != 1 {
                                Some(read_array_with_tag(&mut reader)?)
                            } else {
                                None
                            };
                            let offsets = read_array_with_tag(&mut reader)?;
                            if name_indexes
                                .as_ref()
                                .is_some_and(|names| names.len() != offsets.len())
                            {
                                return Err(corrupt(
                                    offset as u64,
                                    "PSB object name/offset count mismatch",
                                ));
                            }
                            let base = reader.position();
                            let mut names = Vec::new();
                            let mut targets = Vec::with_capacity(offsets.len());
                            for (i, relative) in offsets.iter().enumerate() {
                                // PSB container offsets are unsigned and based after their
                                // arrays, so each child strictly follows its parent.
                                let mut target =
                                    base.checked_add(usize_from_u32(*relative)?).ok_or_else(
                                        || corrupt(base as u64, "PSB child offset overflow"),
                                    )?;
                                if tag == 0x21 {
                                    let name_index = match &name_indexes {
                                        Some(indexes) => usize_from_u32(indexes[i])?,
                                        None => {
                                            let mut key_reader =
                                                BinarySourceReader::new_at(self.data, target)?;
                                            let key_tag = key_reader.read_u8()?;
                                            if !(4..=0x0C).contains(&key_tag) {
                                                return Err(corrupt(
                                                    target as u64,
                                                    "PSB v1 key tag is invalid",
                                                ));
                                            }
                                            let index = read_integer(
                                                &mut key_reader,
                                                usize::from(key_tag - 4),
                                            )?;
                                            target = key_reader.position();
                                            usize::try_from(index).map_err(|_| {
                                                corrupt(
                                                    target as u64,
                                                    "PSB v1 key index is negative or too large",
                                                )
                                            })?
                                        }
                                    };
                                    names.push(
                                        self.names
                                            .get(name_index)
                                            .ok_or_else(|| {
                                                corrupt(
                                                    target as u64,
                                                    "PSB name index out of range",
                                                )
                                            })?
                                            .clone(),
                                    );
                                }
                                targets.push(target);
                            }
                            tasks.push(if tag == 0x20 {
                                ValueTask::List(targets.len())
                            } else {
                                ValueTask::Object(names)
                            });
                            tasks.extend(targets.into_iter().rev().map(ValueTask::Read));
                            continue;
                        }
                        _ => {
                            return Err(corrupt(
                                offset as u64,
                                format!("unknown PSB object tag 0x{tag:02X}"),
                            ));
                        }
                    };
                    values.push(value);
                }
            }
        }
        values.pop().ok_or_else(|| corrupt(0, "missing PSB root"))
    }
}

fn read_encrypted_u32(reader: &mut BinarySourceReader<'_>, stream: &mut PsbStream) -> Result<u32> {
    let mut bytes = reader.read_bytes(4)?.to_vec();
    stream.apply(&mut bytes);
    Ok(BinaryReader::u32_le(&bytes))
}

fn expected_header_len(version: u16) -> u32 {
    if version < 3 {
        40
    } else if version > 3 {
        56
    } else {
        44
    }
}

fn validate_header(header: &PsbHeader, len: u64) -> Result<()> {
    if !(1..=4).contains(&header.version) {
        return Err(corrupt(4, "unsupported PSB version"));
    }

    let min_header = expected_header_len(header.version);
    if header.header_length != 0 && header.header_length < min_header {
        return Err(corrupt(8, "PSB header length is too small"));
    }

    let offsets = [
        header.offset_names,
        header.offset_strings,
        header.offset_strings_data,
        header.offset_chunk_offsets,
        header.offset_chunk_lengths,
        header.offset_chunk_data,
        header.offset_entries,
    ];
    for offset in offsets {
        if u64::from(offset) > len {
            return Err(corrupt(
                u64::from(offset),
                "PSB section offset is out of range",
            ));
        }
    }
    Ok(())
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

fn read_array_with_tag(reader: &mut BinarySourceReader<'_>) -> Result<Vec<u32>> {
    let tag_offset = reader.position();
    let tag = reader.read_u8()?;
    if !(0x0D..=0x14).contains(&tag) {
        return Err(corrupt(tag_offset as u64, "PSB array tag is invalid"));
    }
    read_array_payload(reader, usize::from(tag - 0x0C))
}

fn read_array_payload(reader: &mut BinarySourceReader<'_>, count_width: usize) -> Result<Vec<u32>> {
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

fn read_index(reader: &mut BinarySourceReader<'_>, width: usize) -> Result<u32> {
    let value = reader.read_compact_u64_le(width)?;
    u32::try_from(value)
        .map_err(|_| corrupt(reader.position() as u64, "PSB index does not fit u32"))
}

fn read_integer(reader: &mut BinarySourceReader<'_>, width: usize) -> Result<i64> {
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

fn reader_at(data: &dyn ReadAt, offset: u32) -> Result<BinarySourceReader<'_>> {
    BinarySourceReader::new_at(data, usize_from_u32(offset)?).map_err(Error::from)
}

fn usize_from_u32(value: u32) -> Result<usize> {
    usize::try_from(value).map_err(|_| corrupt(u64::from(value), "value does not fit usize"))
}

fn archive_info_range(range: &[PsbValue], kind: ArchiveInfoKind) -> Result<(u64, u64)> {
    let (start_value, len_value) = match kind {
        ArchiveInfoKind::FileInfo => (range.first(), range.get(1)),
        ArchiveInfoKind::UmdRoot => {
            if range.len() < 2 {
                return Err(corrupt(0, "umd_root range is too short"));
            }
            (range.last(), range.get(range.len() - 2))
        }
    };
    let start = start_value
        .and_then(PsbValue::as_i64)
        .ok_or_else(|| corrupt(0, "archive-info offset is missing"))?;
    let len = len_value
        .and_then(PsbValue::as_i64)
        .ok_or_else(|| corrupt(0, "archive-info length is missing"))?;
    if start < 0 || len < 0 {
        return Err(corrupt(0, "archive-info range is negative"));
    }
    Ok((
        u64::try_from(start).map_err(|_| corrupt(0, "archive-info offset does not fit u64"))?,
        u64::try_from(len).map_err(|_| corrupt(0, "archive-info length does not fit u64"))?,
    ))
}

fn collect_possible_file_names(
    name: &str,
    suffix: &str,
    keep_directory: bool,
    results: &mut Vec<String>,
) {
    if name.trim().is_empty() {
        return;
    }

    if !keep_directory && let Some((_, file_name)) = name.rsplit_once('/') {
        collect_possible_file_names(file_name, suffix, keep_directory, results);
    }

    let lower = name.to_ascii_lowercase();
    if lower != name {
        collect_possible_file_names(&lower, suffix, keep_directory, results);
    }

    let exts = extensions(name);
    if exts.is_empty() {
        results.push(format!("{name}{suffix}"));
        results.push(name.to_string());
    } else if exts
        .first()
        .is_some_and(|ext| ext.eq_ignore_ascii_case(".m"))
        && exts.len() == 1
    {
        results.push(format!("{name}{suffix}"));
        results.push(name.to_string());
        if let Some(stem) = strip_extension(name) {
            results.push(stem.to_string());
        }
    } else {
        if (name.ends_with(".txt") || name.ends_with(".ks")) && suffix.starts_with(".scn") {
            results.push(format!("{name}{suffix}"));
            results.push(name.to_string());
        } else {
            results.push(name.to_string());
            results.push(format!("{name}{suffix}"));
        }

        let mut name2 = name;
        while let Some(stem) = strip_extension(name2) {
            name2 = stem;
            results.push(name2.to_string());
            results.push(format!("{name2}{suffix}"));
        }
    }
}

fn extensions(mut name: &str) -> Vec<&str> {
    let mut exts = Vec::new();
    while let Some(ext) = extension(name) {
        exts.push(ext);
        if let Some(stem) = strip_extension(name) {
            name = stem;
        } else {
            break;
        }
    }
    exts
}

fn extension(name: &str) -> Option<&str> {
    let slash = name.rfind('/').map_or(0, |pos| pos + 1);
    let dot = name[slash..].rfind('.')? + slash;
    if dot + 1 >= name.len() {
        return None;
    }
    Some(&name[dot..])
}

fn strip_extension(name: &str) -> Option<&str> {
    let slash = name.rfind('/').map_or(0, |pos| pos + 1);
    let dot = name[slash..].rfind('.')? + slash;
    if dot == slash {
        return None;
    }
    Some(&name[..dot])
}

fn corrupt(offset: u64, reason: impl Into<String>) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use nvlens_io::BinaryWriter;

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
        assert_eq!(parsed.header.version, 3);
        assert_eq!(parsed.names, vec!["abcde"]);
        assert_eq!(parsed.strings, vec!["hello"]);
        assert_eq!(parsed.resources.len(), 1);

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
    fn archive_info_range_uses_kind_specific_layout() {
        let file_info = vec![
            PsbValue::Number(PsbNumber::Integer(10)),
            PsbValue::Number(PsbNumber::Integer(20)),
        ];
        assert_eq!(
            archive_info_range(&file_info, ArchiveInfoKind::FileInfo).unwrap(),
            (10, 20)
        );

        let umd_root = vec![
            PsbValue::Null,
            PsbValue::Number(PsbNumber::Integer(20)),
            PsbValue::Number(PsbNumber::Integer(10)),
        ];
        assert_eq!(
            archive_info_range(&umd_root, ArchiveInfoKind::UmdRoot).unwrap(),
            (10, 20)
        );
    }

    #[test]
    fn archive_info_possible_names_match_freemote_rules() {
        assert_eq!(
            archive_info_possible_file_names("image/man003", ".psb.m", false),
            [
                "man003.psb.m",
                "man003",
                "image/man003.psb.m",
                "image/man003"
            ]
        );
        assert_eq!(
            archive_info_possible_file_names("bg_c_whit.m", ".psb.m", false),
            ["bg_c_whit.m.psb.m", "bg_c_whit.m", "bg_c_whit"]
        );
        assert_eq!(
            archive_info_possible_file_names("mmm22.ks", ".scn.m", false),
            ["mmm22.ks.scn.m", "mmm22.ks", "mmm22", "mmm22.scn.m"]
        );
    }

    #[test]
    fn validate_header_allows_empty_tail_sections() {
        let header = PsbHeader {
            version: 3,
            header_encrypt: 0,
            header_length: 44,
            offset_names: 44,
            offset_strings: 44,
            offset_strings_data: 44,
            offset_chunk_offsets: 44,
            offset_chunk_lengths: 44,
            offset_chunk_data: 100,
            offset_entries: 44,
            checksum: Some(0),
            offset_extra_chunk_offsets: None,
            offset_extra_chunk_lengths: None,
            offset_extra_chunk_data: None,
        };

        assert!(validate_header(&header, 100).is_ok());
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
