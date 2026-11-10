//! WillPlus AdvHD / Will Co. engine v2 resource archive.
//!
//! Layout (all little-endian):
//! ```text
//! u32  count           entry count
//! u32  index_size      size of the index block in bytes
//! ----                 index starts at offset 8, data starts at base = 8 + index_size
//! per entry: u32 size, u32 offset (relative to base), UTF-16LE NUL-terminated name
//! ```
//! Entry transforms:
//! - scripts (`.ws2` / `.json`) are byte-wise rotated right by 2 bits, unless
//!   the archive name contains "Model"; the final eight WS2 bytes stay plaintext;
//! - `.psp` entries are length-prefixed LZSS;
//! - everything else is raw bytes.

use std::borrow::Cow;
use std::sync::Arc;

use vnlens_core::{
    ArcView, Archive, ArchiveFormat, Entry, Error, Format, ResourceKind, Result, register_archive,
};
use vnlens_crypto::compress::lzss;
use vnlens_io::BinaryReader;

const SIGNATURES: &[u32] = &[0];
const INDEX_START: u64 = 8;

/// The `ARC/WillV2` archive format.
#[derive(Debug, Default)]
struct WillV2Arc;

impl Format for WillV2Arc {
    fn tag(&self) -> &'static str {
        "arc/willv2"
    }

    fn signatures(&self) -> &'static [u32] {
        // No fixed magic: engine identification selects this reader.
        SIGNATURES
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["arc", "ar2"]
    }

    fn description(&self) -> &'static str {
        "Will Co. game engine resource archive v2 (AdvHD)"
    }
}

impl ArchiveFormat for WillV2Arc {
    fn open(
        &self,
        view: &Arc<ArcView>,
        _: &vnlens_core::ArchiveOptions,
    ) -> Result<Box<dyn Archive>> {
        match parse_index(view) {
            Some(entries) => Ok(Box::new(WillV2Archive {
                view: Arc::clone(view),
                entries,
            })),
            None => Err(Error::Corrupt {
                offset: 0,
                reason: "Invalid AdvHD v2 index".into(),
            }),
        }
    }
}

/// Parses the index; any mismatch returns `None` (i.e. "not this format").
fn parse_index(view: &ArcView) -> Option<Vec<Entry>> {
    let count = u64::from(view.read_u32_le(0).ok()?);
    let index_size = u64::from(view.read_u32_le(4).ok()?);
    let base = INDEX_START.checked_add(index_size)?;
    // Each record needs two u32 fields and at least its UTF-16 terminator.
    if base > view.len() || count > index_size / 10 {
        return None;
    }
    let index = view.slice(INDEX_START, index_size).ok()?;
    let mut reader = BinaryReader::new(index);
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(usize::try_from(count).ok()?)
        .ok()?;
    for _ in 0..count {
        let size = u64::from(reader.read_u32_le().ok()?);
        let rel = u64::from(reader.read_u32_le().ok()?);
        let offset = base.checked_add(rel)?;
        let mut units = Vec::new();
        loop {
            let unit = reader.read_u16_le().ok()?;
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        let name = String::from_utf16(&units).ok()?;

        let entry = Entry {
            kind: ResourceKind::Unknown,
            name,
            offset,
            size,
            packed: None,
        };
        if !entry.check_placement(view.len()) {
            return None;
        }
        entries.push(entry);
    }
    // The index must end exactly at the data boundary, otherwise not this format.
    if reader.remaining() != 0 {
        return None;
    }
    Some(entries)
}

/// An opened `ARC/WillV2` archive.
#[derive(Debug)]
struct WillV2Archive {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
}

impl Archive for WillV2Archive {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn vnlens_io::ReadAt>>> {
        if is_script(&entry.name) || has_ext(&entry.name, "psp") {
            return Ok(None);
        }
        Ok(Some(Arc::new(vnlens_io::RangeSource::new(
            self.view.clone(),
            entry.offset,
            entry.size,
        )?)))
    }

    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }

    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let raw = self.view.slice(entry.offset, entry.size)?;

        // When the archive name contains "Model", scripts are left unscrambled
        // (matching engine behavior).
        let is_model = self.view.file_name().contains("Model");
        if is_script(&entry.name) && !is_model {
            let mut data = raw.to_vec();
            let end = if has_ext(&entry.name, "ws2") {
                data.len()
                    .checked_sub(8)
                    .ok_or_else(|| vnlens_io::BinaryIo::unexpected_eof("WS2 footer is missing"))?
            } else {
                data.len()
            };
            for byte in &mut data[..end] {
                *byte = byte.rotate_right(2);
            }
            return Ok(Cow::Owned(data));
        }
        if has_ext(&entry.name, "psp") {
            let data = lzss::decompress_prefixed(raw).map_err(|e| Error::Corrupt {
                offset: entry.offset,
                reason: e.to_string(),
            })?;
            return Ok(Cow::Owned(data));
        }
        Ok(Cow::Borrowed(raw))
    }
}

fn is_script(name: &str) -> bool {
    has_ext(name, "ws2") || has_ext(name, "json")
}

fn has_ext(name: &str, ext: &str) -> bool {
    name.rsplit('.')
        .next()
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

register_archive!(WillV2Arc);

#[cfg(test)]
#[path = "../../tests/will/arc.rs"]
mod tests;
