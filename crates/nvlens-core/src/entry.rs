//! Archive entry model and related validation.

/// A single file entry inside an archive.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Relative path within the archive; absolute paths and `..` are rejected.
    pub name: String,
    /// Resource category.
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
    Audio,
    Script,
    Video,
    Unknown,
}

impl ResourceKind {
    /// Roughly guesses the category from a file name extension. Used only for
    /// display and defaults; format implementations may override it.
    pub fn guess_from_name(name: &str) -> Self {
        let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        match ext.as_str() {
            "png" | "pna" | "bmp" | "jpg" | "jpeg" | "tga" | "psb" | "psd" | "wip" => Self::Image,
            "ogg" | "wav" | "mp3" | "flac" => Self::Audio,
            "ws2" | "json" | "scr" | "txt" | "ini" => Self::Script,
            "mpg" | "mp4" | "wmv" | "avi" => Self::Video,
            _ => Self::Unknown,
        }
    }
}

impl Entry {
    /// Whether the entry lies fully within `[0, max_offset)` (guards against
    /// out-of-range offsets and integer overflow).
    pub fn check_placement(&self, max_offset: u64) -> bool {
        self.offset < max_offset && self.size <= max_offset && self.offset <= max_offset - self.size
    }

    /// Whether the entry name is safe: non-empty, not absolute, no `..` traversal.
    pub fn has_valid_name(&self) -> bool {
        let n = &self.name;
        !n.is_empty()
            && !n.starts_with('/')
            && !n.starts_with('\\')
            && n.get(1..2) != Some(":") // drive letter
            && !n.split(['/', '\\']).any(|part| part == "..")
    }
}

/// Whether an archive entry count is within a sane range. Used to cap
/// allocations and reject corrupt or malicious indexes before allocating.
pub fn is_sane_count(count: i64) -> bool {
    count > 0 && count < 0x40000
}
