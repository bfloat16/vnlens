//! Cipher primitives.

pub mod blowfish;
pub mod mdf;
pub mod psb_stream;
pub mod scramble;
pub mod xor;

/// Cipher construction error, raised when a supplied key/constant table has the
/// wrong size.
#[derive(Debug, thiserror::Error)]
pub enum CipherError {
    #[error("cipher key must not be empty")]
    EmptyKey,
    #[error("blowfish constant table must be at least {expected} bytes, got {got}")]
    BadBlowfishTable { expected: usize, got: usize },
    #[error("scramble base table must be exactly {expected} bytes, got {got}")]
    BadScrambleBase { expected: usize, got: usize },
}
