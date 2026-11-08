//! nvlens low-level I/O layer.
//!
//! This crate is the single source of all binary read/write operations in the
//! project (see [`binary`]), and owns the memory-mapped [`ArcView`] and the
//! unified logging manager ([`log`]). Unsafe here is confined to memory mapping.
#![deny(unsafe_code)]

mod binary;
mod source;
mod view;

pub mod filesystem;
pub mod log;
pub mod pe;

pub use binary::{BinaryIo, BinaryReader, BinaryWriter, BitOrder, BitReader, Endian};
pub use source::{BinarySourceReader, ReadAt};
pub use view::ArcView;
