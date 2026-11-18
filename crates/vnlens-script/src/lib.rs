//! vnlens script-format decoders and text extractors (organized by engine).
//!
//! `lib.rs` only exposes the public surface; logic lives in per-engine modules.
#![forbid(unsafe_code)]

mod ages_mk2;
mod artemis;
mod bgi;
mod csystem;
mod entisgls;
pub mod escude;
mod exhibit;
mod format;
mod gss;
pub use vnlens_core::ir;
mod kaleido;
pub mod krkr;
mod mages;
mod middleware;
mod nscripter;
mod otomate;
mod propeller;
mod reallive;
pub mod rugp;
mod siglus;
pub mod softpal;
mod systemnnn;
mod will;
pub mod yuris;
pub use format::{
    ScriptFormat, ScriptRegistration, decode_as, decode_text_as, decode_with_resources_as,
    disassemble_as, disassemble_cancellable_as,
};

pub use ages_mk2::epk;

/// Forces this crate to be linked so its format registrations are included in
/// the final binary.
pub fn init() {}
