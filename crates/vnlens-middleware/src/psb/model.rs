//! PSB metadata and tree values; payloads remain references to source ranges.
use crate::mdf::MdfKey;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Parsed PSB file.
#[derive(Clone, Debug)]
pub struct Psb {
    /// Original compression-shell framing, when opened through PsbFile.
    pub shell: Option<crate::mdf::ShellHeader>,
    pub header: PsbHeader,
    /// Encryption actually applied to the input, independent of header flags.
    pub encryption: PsbEncryption,
    /// Size of the decoded PSB backing stream, before materializing its tree.
    pub data_len: u64,
    pub names: Vec<String>,
    pub strings: Vec<String>,
    pub resources: Vec<PsbResource>,
    pub extra_resources: Vec<PsbResource>,
    pub root: PsbValue,
    /// Serialized values keyed by source offset, including shared children.
    pub nodes: BTreeMap<u64, PsbNode>,
}

/// A named serialized member exposed as a virtual file. Values borrow the
/// complete retained document, including their string and resource context.
#[derive(Clone, Debug)]
pub struct PsbValueFile {
    pub document: Arc<Psb>,
    /// None selects a non-object or empty root; Some selects an original key.
    pub key: Option<String>,
}

impl PsbValueFile {
    /// Resolves the native value without cloning or serializing the tree.
    #[must_use]
    pub fn value(&self) -> Option<&PsbValue> {
        match &self.key {
            Some(key) => self.document.root.as_object()?.get(key),
            None => Some(&self.document.root),
        }
    }
}

/// PSB file header.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PsbHeader {
    pub version: u16,
    /// Original flags, including bits not interpreted by this reader.
    pub flags: u16,
    /// In v1 this is the key-offset array position, rather than a length.
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

/// Source representation of a tagged value. Container sizes cover their tag
/// and index arrays; children have their own records and may be shared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PsbNode {
    pub offset: u64,
    pub size: u64,
    pub tag: u8,
    pub children: Vec<PsbChild>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PsbChild {
    pub offset: u64,
    pub name_index: Option<u64>,
    /// v1 keys are serialized immediately before the child value.
    pub key_offset: Option<u64>,
    pub key_tag: Option<u8>,
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
    /// Tag zero is the native empty/undefined value, distinct from null.
    Void,
    Null,
    Bool(bool),
    Number(PsbNumber),
    Array(Vec<u64>),
    String {
        index: u32,
        value: String,
    },
    Resource {
        index: u32,
        is_extra: bool,
    },
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
#[derive(Clone, Copy)]
pub struct ParseOptions<'a> {
    pub psb_key: Option<u32>,
    pub mdf_key: Option<MdfKey<'a>>,
    /// Auto uses header ranges and the name-array prefix, without retrying a
    /// failed tree parse. Select an explicit mode for ambiguous legacy files.
    pub encryption: PsbEncryption,
    /// PSB strings are NUL-terminated bytes. UTF-8 strings and v2+ names also
    /// accept CESU-8 surrogate pairs emitted by E-mote tools.
    pub encoding: &'static encoding_rs::Encoding,
    pub cancelled: Option<&'a AtomicBool>,
}

impl Default for ParseOptions<'_> {
    fn default() -> Self {
        Self {
            psb_key: None,
            mdf_key: None,
            encryption: PsbEncryption::Auto,
            encoding: encoding_rs::UTF_8,
            cancelled: None,
        }
    }
}

/// PSB header and metadata-body encryption are independent. Resource chunks
/// are outside the encrypted body range.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PsbEncryption {
    #[default]
    Auto,
    None,
    Header,
    Body,
    Full,
}

impl std::fmt::Debug for ParseOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParseOptions").finish_non_exhaustive()
    }
}
