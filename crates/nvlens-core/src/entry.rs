//! Archive entry model and related validation.

/// A single file entry inside an archive.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Name as stored by the format; the output layer maps it to a local path.
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
    /// Structured values and configuration objects that are not executable scripts.
    Data,
    Font,
    Video,
    Unknown,
}

impl ResourceKind {
    /// Roughly guesses the category from a file name extension. Used only for
    /// display and defaults; format implementations may override it.
    #[must_use]
    pub fn guess_from_name(name: &str) -> Self {
        let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        match ext.as_str() {
            "png" | "pna" | "bmp" | "jpg" | "jpeg" | "tga" | "psb" | "psd" | "wip" | "g00"
            | "gyu" | "dlt" | "mos" | "dwq" => Self::Image,
            "ogg" | "wav" | "mp3" | "flac" | "nwa" | "vaw" | "wgq" => Self::Audio,
            "json" | "scr" | "txt" | "ini" | "ss" | "gan" | "tjs" | "ks" | "scn" | "rld"
            | "rnf" | "ws2" | "lua" | "luac" | "spt" | "xtx" | "fxf" | "mml" => Self::Script,
            "mpg" | "mp4" | "wmv" | "avi" | "omv" | "ogv" => Self::Video,
            "ttf" | "otf" | "ttc" | "woff" | "woff2" | "fon" | "fnt" => Self::Font,
            _ => Self::Unknown,
        }
    }
}

impl Entry {
    /// Whether the entry lies fully within `[0, max_offset)` (guards against
    /// out-of-range offsets and integer overflow).
    #[must_use]
    pub fn check_placement(&self, max_offset: u64) -> bool {
        self.offset <= max_offset && self.size <= max_offset - self.offset
    }
}
