//! Cipher primitives.

pub mod aes;
pub mod blowfish;
pub mod criware;
pub mod csystem;
pub mod enigma;
pub mod escude;
pub mod exhibit;
pub mod hxv4;
pub mod mdf;
mod mt19937;
pub mod psb_stream;
pub mod rugp;
pub mod scramble;
pub mod softpal;
pub mod xor;
pub mod xp3;

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
