//! Unified error type.

/// nvlens library error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Data does not match the selected format. Directed archive dispatch never
    /// uses this error to fall back to another reader.
    #[error("invalid format")]
    InvalidFormat,

    /// Recognized as some format, but the feature is not yet implemented.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// Recognized as some format, but the data is corrupt.
    #[error("data corrupted at 0x{offset:x}: {reason}")]
    Corrupt { offset: u64, reason: String },

    /// The archive needs an unknown encryption scheme (key / game title).
    #[error("unknown encryption scheme{}", .0.as_deref().map(|s| format!(": {s}")).unwrap_or_default())]
    UnknownScheme(Option<String>),

    /// Cancelled by the user (e.g. declined to provide a key); not corruption.
    #[error("operation cancelled")]
    Cancelled,
}

/// Library-wide `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;
