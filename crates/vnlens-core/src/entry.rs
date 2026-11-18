//! Archive entry model and related validation.

/// A single file entry inside an archive.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Name as stored by the format; the output layer maps it to a local path.
    pub name: String,
    /// Resource category declared by the index. Name-based classification is
    /// supplied by the identified engine; absent index information is Unknown.
    pub kind: ResourceKind,
    /// Absolute byte offset within the archive file.
    pub offset: u64,
    /// Stored byte length (for packed entries, the compressed size).
    pub size: u64,
    /// Compression info; `None` means stored uncompressed.
    pub packed: Option<Packed>,
}

/// Extra information for a packed entry.
#[derive(Clone, Copy, Debug)]
pub struct Packed {
    /// Size in bytes after decompression.
    pub unpacked_size: u64,
    /// Whether the entry is actually compressed (some formats flag this inline).
    pub is_packed: bool,
}

/// Resource category, replacing free-form strings with a typed enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceKind {
    Archive,
    Image,
    Model,
    Audio,
    Script,
    /// Structured values and configuration objects that are not executable scripts.
    Data,
    Font,
    Video,
    Unknown,
}

impl Entry {
    /// Whether the entry lies fully within `[0, max_offset)` (guards against
    /// out-of-range offsets and integer overflow).
    #[must_use]
    pub fn check_placement(&self, max_offset: u64) -> bool {
        self.offset <= max_offset && self.size <= max_offset - self.offset
    }
}
