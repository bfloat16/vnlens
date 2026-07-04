//! nvlens archive-format implementations (organized by engine).
#![forbid(unsafe_code)]

mod will;

pub use will::WillV2Arc;

/// Forces this crate to be linked so its `register_archive!` records are
/// included in the final binary. Binaries call this once before using
/// [`nvlens_core::Catalog`].
pub fn init() {}
