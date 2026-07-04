//! nvlens core abstraction layer: entry model, format traits, registry,
//! probing, and the shared error type.
//!
//! This crate contains no concrete format implementations; it only defines the
//! contracts shared across layers.
#![forbid(unsafe_code)]

mod catalog;
mod entry;
mod error;
mod format;

pub use catalog::{Catalog, Opened};
pub use entry::{Entry, Packed, ResourceKind, is_sane_count};
pub use error::{Error, Result};
pub use format::{Archive, ArchiveFormat, ArchiveRegistration, Format};

// Referenced by the `register_archive!` macro when expanded in downstream
// crates, so they do not need a direct dependency on `inventory`.
#[doc(hidden)]
pub use inventory;

// Re-export the I/O view so format crates only need to depend on nvlens-core.
pub use nvlens_io::ArcView;
