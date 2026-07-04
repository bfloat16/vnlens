//! nvlens low-level I/O layer.
//!
//! This crate is the single source of all binary read/write operations in the
//! project (see [`binary`]), and owns the memory-mapped [`ArcView`] and the
//! unified logging manager ([`log`]). It is the only crate allowed to use
//! `unsafe`, and solely for memory mapping.

mod binary;
mod view;

pub mod log;

pub use binary::{BinaryIo, BinaryReader, BinaryWriter, Endian};
pub use view::ArcView;
