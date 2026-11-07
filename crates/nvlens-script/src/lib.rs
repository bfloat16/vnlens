//! nvlens script-format decoders and text extractors (organized by engine).
//!
//! `lib.rs` only exposes the public surface; logic lives in per-engine modules.
#![forbid(unsafe_code)]

mod ages_mk2;
mod emote;
mod format;
pub mod ir;
pub mod yuris;
pub use format::{ScriptFormat, ScriptRegistration, disassemble_as};

pub use ages_mk2::epk;
pub use emote::mdf;
pub use emote::psb;

/// Forces this crate to be linked so its format registrations are included in
/// the final binary.
pub fn init() {}
