//! SystemNNN split indexes. GPK uses GTB name/offset tables; VPK uses VTB
//! fixed records and a terminal offset. Payload bytes remain borrowed and
//! are interpreted only by the image/audio domain when requested.
mod gpk;
mod vpk;

use std::{borrow::Cow, sync::Arc};
use vnlens_core::{Archive, Entry, Error, Result};
use vnlens_io::ArcView;

struct Package {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
}
impl Archive for Package {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn vnlens_io::ReadAt>>> {
        Ok(Some(Arc::new(vnlens_io::RangeSource::new(
            self.view.clone(),
            entry.offset,
            entry.size,
        )?)))
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
}
fn corrupt(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}
fn name(bytes: &[u8]) -> Result<String> {
    let bytes = bytes.split(|&b| b == 0).next().unwrap_or_default();
    let (name, _, errors) = encoding_rs::SHIFT_JIS.decode(bytes);
    if errors {
        return Err(corrupt(0, "Invalid SystemNNN CP932 entry name"));
    }
    Ok(name.into_owned())
}

#[cfg(test)]
#[path = "../../tests/systemnnn/mod.rs"]
mod tests;
