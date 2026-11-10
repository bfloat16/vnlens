//! PSB metadata, source parsing, archive indexes and text export.
mod archive_info;
mod header;
mod model;
mod read;
mod text;
mod value;

pub use archive_info::{
    ArchiveInfoEntry, ArchiveInfoKind, archive_info_entries, archive_info_possible_file_names,
    archive_info_suffix,
};
use model::PsbHeader;
pub use model::{ParseOptions, Psb, PsbNumber, PsbResource, PsbValue};
pub use read::{open_source, parse_source};

use vnlens_core::Error;
const PSB_MAGIC: &[u8; 4] = b"PSB\0";

fn corrupt(offset: u64, reason: impl Into<String>) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}
