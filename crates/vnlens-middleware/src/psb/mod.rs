//! PSB metadata, source parsing, archive indexes and text export.
mod archive_info;
mod container;
mod header;
mod media;
mod model;
mod read;
mod source;
mod text;
mod value;

pub use archive_info::{
    ArchiveInfoEntry, ArchiveInfoKind, archive_info_entries, archive_info_possible_file_names,
    archive_info_suffix,
};
pub use container::PsbFile;
pub use model::{
    ParseOptions, Psb, PsbChild, PsbEncryption, PsbHeader, PsbNode, PsbNumber, PsbResource,
    PsbValue, PsbValueFile,
};
pub use read::{open_source, parse_shared_source, parse_source, parse_source_with_options};

use vnlens_core::Error;
const PSB_MAGIC: &[u8; 4] = b"PSB\0";

fn corrupt(offset: u64, reason: impl Into<String>) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

fn check_cancelled(options: ParseOptions<'_>) -> vnlens_core::Result<()> {
    if options
        .cancelled
        .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
    {
        return Err(Error::Cancelled);
    }
    Ok(())
}
