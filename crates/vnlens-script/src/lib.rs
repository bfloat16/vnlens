//! vnlens script-format decoders and text extractors (organized by engine).
//!
//! `lib.rs` only exposes the public surface; logic lives in per-engine modules.
#![forbid(unsafe_code)]

mod ages_mk2;
mod bgi;
mod csystem;
pub mod escude;
mod exhibit;
mod format;
pub use vnlens_core::ir;
mod kaleido;
pub mod krkr;
mod mages;
mod middleware;
mod propeller;
mod reallive;
pub mod rugp;
mod siglus;
pub mod softpal;
mod systemnnn;
mod will;
pub mod yuris;
pub use format::disassemble_with_options_as;
pub use format::{ScriptFormat, ScriptRegistration, decode_as, decode_text_as, disassemble_as};

pub use ages_mk2::epk;

/// Forces this crate to be linked so its format registrations are included in
/// the final binary.
pub fn init() {}
