//! nvlens audio-format decoders (organized by engine).
//!
//! `lib.rs` only exposes the public surface; logic lives in per-engine modules.
#![forbid(unsafe_code)]

mod ages_mk2;
pub mod bgi;
mod format;
pub mod levels;
mod model;
mod siglus;
pub mod spectrogram;
mod standard;

pub use format::{AudioFormat, AudioRegistration, decode, decode_cancellable, metadata};
pub use model::{AudioMeta, Pcm};

pub use ages_mk2::fcd;

/// Forces this crate to be linked so its format registrations are included in
/// the final binary.
pub fn init() {}
