//! vnlens archive-format implementations (organized by engine).
#![forbid(unsafe_code)]

mod ages_mk2;
mod bgi;
mod csystem;
mod emote;
mod entisgls;
mod escude;
mod exhibit;
pub mod krkr;
mod mages;
mod propeller;
mod psb;
mod reallive;
mod rugp;
mod siglus;
mod softpal;
mod systemnnn;
mod will;
mod yuris;

/// Forces this crate to be linked so its `register_archive!` records are
/// included in the final binary. Binaries call this once before using
/// [`vnlens_core::Catalog`].
pub fn init() {}
