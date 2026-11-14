//! CRIWARE containers and metadata, independent of their game host. UTF tables
//! retain their schemas and lazy binary references; containers only index
//! requested resources. SDK reference: criFsBinder/CriAtomExAcb/CriAtomAwb.
pub mod acb;
pub mod audio;
pub mod awb;
pub mod cpk;
pub mod hca;
pub mod usm;
pub mod utf;

use std::sync::Arc;
use vnlens_core::{Error, Result};
use vnlens_io::{BinaryIo, RangeSource, ReadAt};

fn corrupt(offset: u64, reason: impl Into<String>) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| corrupt(a, "CRI offset overflow"))
}
fn memory(size: u64) -> Result<usize> {
    usize::try_from(size).map_err(|_| {
        Error::Unsupported("CRI range cannot fit in address space; use a streaming source".into())
    })
}
fn bounds(source: &dyn ReadAt, offset: u64, size: u64) -> Result<()> {
    if offset > source.len() || size > source.len() - offset {
        return Err(BinaryIo::unexpected_eof("CRI range exceeds source").into());
    }
    Ok(())
}
fn range(source: Arc<dyn ReadAt>, offset: u64, size: u64) -> Result<Arc<dyn ReadAt>> {
    Ok(Arc::new(RangeSource::new(source, offset, size)?))
}

fn text(bytes: &[u8]) -> Result<String> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Ok(text.into());
    }
    let (text, _, errors) = encoding_rs::SHIFT_JIS.decode(bytes);
    if errors {
        return Err(corrupt(0, "Invalid CRI text encoding"));
    }
    Ok(text.into_owned())
}

#[cfg(test)]
#[path = "../../tests/criware/mod.rs"]
mod tests;
