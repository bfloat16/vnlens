//! PSB metadata and tree values; payloads remain references to source ranges.
use super::super::mdf::MdfKey;
use std::collections::BTreeMap;

/// Parsed PSB file.
#[derive(Clone, Debug)]
pub struct Psb {
    /// Size of the decoded PSB backing stream, before materializing its tree.
    pub data_len: u64,
    pub names: Vec<String>,
    pub strings: Vec<String>,
    pub resources: Vec<PsbResource>,
    pub extra_resources: Vec<PsbResource>,
    pub root: PsbValue,
}

/// PSB file header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PsbHeader {
    pub version: u16,
    pub header_length: u32,
    pub offset_names: u32,
    pub offset_strings: u32,
    pub offset_strings_data: u32,
    pub offset_chunk_offsets: u32,
    pub offset_chunk_lengths: u32,
    pub offset_chunk_data: u32,
    pub offset_entries: u32,
    pub offset_extra_chunk_offsets: Option<u32>,
    pub offset_extra_chunk_lengths: Option<u32>,
    pub offset_extra_chunk_data: Option<u32>,
}

impl PsbHeader {
    /// FreeMote-compatible heuristic for encrypted headers.
    #[must_use]
    pub(super) fn is_header_encrypted(&self) -> bool {
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
            Self::Number(PsbNumber::Integer(value)) => Some(*value),
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
