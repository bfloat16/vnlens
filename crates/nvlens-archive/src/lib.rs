//! nvlens archive-format implementations (organized by engine).
#![forbid(unsafe_code)]

mod ages_mk2;
mod bgi;
mod emote;
mod escude;
mod exhibit;
pub mod krkr;
mod propeller;
mod rugp;
mod siglus;
mod systemnnn;
mod will;
mod yuris;

/// Forces this crate to be linked so its `register_archive!` records are
/// included in the final binary. Binaries call this once before using
/// [`nvlens_core::Catalog`].
pub fn init() {}
