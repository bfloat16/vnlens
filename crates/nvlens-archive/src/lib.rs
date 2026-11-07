//! nvlens archive-format implementations (organized by engine).
#![forbid(unsafe_code)]

mod ages_mk2;
mod emote;
mod will;
mod yuris;

pub use ages_mk2::FpdArc;
pub use emote::{EmoteArchiveInfo, EmotePsbResources};
pub use will::WillV2Arc;
pub use yuris::YpfArchiveFormat;

/// Forces this crate to be linked so its `register_archive!` records are
/// included in the final binary. Binaries call this once before using
/// [`nvlens_core::Catalog`].
pub fn init() {}
