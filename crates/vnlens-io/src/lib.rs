//! vnlens low-level I/O layer.
//!
//! This crate is the single source of all binary read/write operations in the
//! project (see [`binary`]), and owns the memory-mapped [`ArcView`] and the
//! unified logging manager ([`log`]). Unsafe here is confined to memory mapping.
#![deny(unsafe_code)]

mod binary;
mod files;
mod source;
mod view;

pub mod filesystem;
pub mod log;
pub mod pe;

pub use binary::{
    BinaryIo, BinaryReader, BinaryWriter, BitOrder, BitReader, BitWriter, Endian, InterleavedBits,
    StreamBitReader,
};
pub use files::{DirectoryEntry, FileMetadata, FileSystem};
pub use source::{
    BinarySourceReader, RangeSource, ReadAt, ReadFactory, ReadSeek, ReplayReader, ReplaySource,
};
pub use view::ArcView;
