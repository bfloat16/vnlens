//! nvlens script-format decoders and text extractors (organized by engine).
//!
//! `lib.rs` only exposes the public surface; logic lives in per-engine modules.
#![forbid(unsafe_code)]

mod ages_mk2;
mod bgi;
mod emote;
mod exhibit;
mod format;
pub mod ir;
pub mod krkr;
mod lua;
mod siglus;
mod will;
pub mod yuris;
pub use format::disassemble_with_options_as;
pub use format::{ScriptFormat, ScriptRegistration, decode_as, decode_text_as, disassemble_as};

pub use ages_mk2::epk;
pub use emote::mdf;
pub use emote::psb;

/// Forces this crate to be linked so its format registrations are included in
/// the final binary.
pub fn init() {}
