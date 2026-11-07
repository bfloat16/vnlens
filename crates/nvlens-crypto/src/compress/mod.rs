//! Decompression routines.

pub mod lzss;
pub mod zlib;

/// Decompression error.
#[derive(Debug, thiserror::Error)]
pub enum CompressError {
    /// Input was exhausted before decompression completed.
    #[error("truncated input at {pos} (expected more bytes)")]
    Truncated { pos: usize },
    /// A zlib/deflate stream failed to decode (e.g. wrong key yields non-zlib bytes).
    #[error("zlib inflate failed")]
    Inflate,
    /// A decompressed output would exceed the caller-supplied limit.
    #[error("decompressed output exceeds limit {limit}")]
    OutputTooLarge { limit: usize },
}
