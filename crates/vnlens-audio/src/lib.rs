//! vnlens audio-format decoders (organized by engine).
//!
//! `lib.rs` only exposes the public surface; logic lives in per-engine modules.
#![forbid(unsafe_code)]

mod ages_mk2;
pub mod bgi;
pub mod csystem;
mod entisgls;
mod format;
pub mod levels;
mod model;
pub mod rugp;
mod siglus;
pub mod spectrogram;
mod standard;
mod systemnnn;
mod xwma;

pub use format::{AudioFormat, AudioRegistration, decode_as, decode_cancellable_as, metadata_as};
pub use model::{AudioMeta, Pcm};

pub use ages_mk2::fcd;

/// Forces this crate to be linked so its format registrations are included in
/// the final binary.
pub fn init() {}
