//! Decompression routines.

mod copy;

pub mod acp;
pub mod bgi;
pub mod csystem;
pub mod enigma;
pub mod erisa;
pub mod exhibit;
pub mod lzf;
pub mod lzss;
pub mod pdt;
pub mod rugp;
pub mod siglus;
pub mod snappy;
pub mod softpal;
pub mod tlg;
pub mod tlg6;
pub mod zlib;
pub mod zstd;

/// Decompression error.
#[derive(Debug, thiserror::Error)]
pub enum CompressError {
    #[error("invalid compressed data at {pos}: {reason}")]
    InvalidData { pos: usize, reason: &'static str },
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
