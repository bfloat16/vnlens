//! Decompression routines.

pub mod lzss;

/// Decompression error.
#[derive(Debug, thiserror::Error)]
pub enum CompressError {
    /// Input was exhausted before decompression completed.
    #[error("truncated input at {pos} (expected more bytes)")]
    Truncated { pos: usize },
}
