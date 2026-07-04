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
//!   the archive name contains "Model";
//! - `.psp` entries are length-prefixed LZSS;
//! - everything else is raw bytes.

use std::borrow::Cow;
use std::sync::Arc;

use nvlens_core::{
    ArcView, Archive, ArchiveFormat, Entry, Error, Format, ResourceKind, Result, is_sane_count,
    register_archive,
};
use nvlens_crypto::compress::lzss;

const INDEX_START: u64 = 8;

/// The `ARC/WillV2` archive format.
#[derive(Debug, Default)]
pub struct WillV2Arc;

impl Format for WillV2Arc {
    fn tag(&self) -> &'static str {
        "arc/willv2"
    }

    fn description(&self) -> &'static str {
        "Will Co. game engine resource archive v2 (AdvHD)"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["arc", "ar2"]
    }
}

impl ArchiveFormat for WillV2Arc {
    fn try_open(&self, view: &Arc<ArcView>) -> Result<Option<Box<dyn Archive>>> {
        match parse_index(view) {
            Some(entries) => Ok(Some(Box::new(WillV2Archive {
                view: Arc::clone(view),
                entries,
            }))),
            None => Ok(None),
        }
    }
}

/// Parses the index; any mismatch returns `None` (i.e. "not this format").
fn parse_index(view: &ArcView) -> Option<Vec<Entry>> {
    let count = view.read_i32_le(0).ok()?;
    if !is_sane_count(count as i64) {
        return None;
    }
    let index_size = view.read_u32_le(4).ok()? as u64;
    let base = INDEX_START.checked_add(index_size)?;
    if base >= view.len() {
        return None;
    }

    let mut off = INDEX_START;
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if off >= base {
            return None;
        }
        let size = view.read_u32_le(off).ok()? as u64;
        let rel = view.read_u32_le(off + 4).ok()? as u64;
        let offset = base.checked_add(rel)?;
        off += 8;

        // UTF-16LE NUL-terminated name; must stay within the index block.
        let mut units = Vec::new();
        loop {
            if off >= base {
                return None;
            }
            let unit = view.read_u16_le(off).ok()?;
            off += 2;
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        if units.is_empty() {
            return None;
        }
        let name = String::from_utf16(&units).ok()?;

        let entry = Entry {
            kind: ResourceKind::guess_from_name(&name),
            name,
            offset,
            size,
            packed: None,
        };
        if !entry.check_placement(view.len()) || !entry.has_valid_name() {
            return None;
        }
        entries.push(entry);
    }
    // The index must end exactly at the data boundary, otherwise not this format.
    if off != base {
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

    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let raw = self.view.slice(entry.offset, entry.size)?;

        // When the archive name contains "Model", scripts are left unscrambled
        // (matching engine behavior).
        let is_model = self.view.file_name().contains("Model");
        if is_script(&entry.name) && !is_model {
            let data = raw.iter().map(|b| b.rotate_right(2)).collect();
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ext_matching() {
        assert!(is_script("scene.ws2"));
        assert!(is_script("data.JSON"));
        assert!(!is_script("bg.png"));
        assert!(has_ext("x.PSP", "psp"));
    }

    #[test]
    fn rotate_right_two_is_reversible() {
        // Rotating right by 2 bits must be reversible (rotate left by 2).
        for b in 0u8..=255 {
            assert_eq!(b.rotate_right(2).rotate_left(2), b);
        }
    }
}
