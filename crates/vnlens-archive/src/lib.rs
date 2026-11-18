//! vnlens archive-format implementations (organized by engine).
#![forbid(unsafe_code)]

mod ages_mk2;
mod artemis;
mod bgi;
mod criware;
mod csystem;
mod emote;
mod entisgls;
mod escude;
mod exhibit;
mod gss;
pub mod krkr;
mod mages;
pub mod ns;
mod nscripter;
pub mod otomate;
mod propeller;
mod psb;
mod reallive;
mod rugp;
mod siglus;
mod softpal;
mod systemnnn;
mod tamsoft;
mod will;
mod yuris;

/// Forces this crate to be linked so its `register_archive!` records are
/// included in the final binary. Binaries call this once before using
/// [`vnlens_core::Catalog`].
pub fn init() {}
