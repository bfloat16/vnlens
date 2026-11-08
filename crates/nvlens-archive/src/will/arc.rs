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

use nvlens_core::{
    ArcView, Archive, ArchiveFormat, Entry, Error, Format, ResourceKind, Result, register_archive,
};
use nvlens_crypto::compress::lzss;
use nvlens_io::BinaryReader;

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
        _: &nvlens_core::ArchiveOptions,
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
            kind: ResourceKind::guess_from_name(&name),
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
                    .ok_or_else(|| nvlens_io::BinaryIo::unexpected_eof("WS2 footer is missing"))?
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nvlens_core::ArchiveOptions;
    use nvlens_io::BinaryWriter;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestDir(std::path::PathBuf);
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn build_arc(records: &[(&str, &[u8])]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut data = Vec::new();
        for &(name, payload) in records {
            let mut header = [0u8; 8];
            BinaryWriter::u32_le(u32::try_from(payload.len()).unwrap(), &mut header[..4]);
            BinaryWriter::u32_le(u32::try_from(data.len()).unwrap(), &mut header[4..8]);
            index.extend_from_slice(&header);
            for unit in name.encode_utf16().chain(std::iter::once(0)) {
                let mut word = [0u8; 2];
                BinaryWriter::u16_le(unit, &mut word);
                index.extend_from_slice(&word);
            }
            data.extend_from_slice(payload);
        }
        let mut out = vec![0u8; 8];
        BinaryWriter::u32_le(u32::try_from(records.len()).unwrap(), &mut out[..4]);
        BinaryWriter::u32_le(u32::try_from(index.len()).unwrap(), &mut out[4..8]);
        out.extend_from_slice(&index);
        out.extend_from_slice(&data);
        out
    }

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

    #[test]
    fn mounts_lazily_and_applies_entry_transforms() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = TestDir(std::env::temp_dir().join(format!(
            "nvlens-will-arc-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        fs::create_dir_all(&dir.0).unwrap();

        let ws2_plain = b"script\x01\x02\x04\x08\x10\x20\x40\x80";
        let ws2_stored: Vec<u8> = ws2_plain
            .iter()
            .enumerate()
            .map(|(i, b)| if i < 6 { b.rotate_left(2) } else { *b })
            .collect();
        let psp_valid = [3, 0, 0, 0, 0b0000_0111, b'A', b'B', b'C'];
        let bytes = build_arc(&[
            ("scene.ws2", &ws2_stored),
            ("ok.psp", &psp_valid),
            ("corrupt.psp", b"short"),
            ("raw.bin", b"raw"),
        ]);

        let rio_path = dir.0.join("Rio.arc");
        fs::write(&rio_path, &bytes).unwrap();
        let archive = WillV2Arc
            .open(
                &Arc::new(ArcView::open(&rio_path).unwrap()),
                &ArchiveOptions::default(),
            )
            .unwrap();
        let entries = archive.entries();
        assert_eq!(entries.len(), 4);
        assert_eq!(&*archive.open_entry(&entries[0]).unwrap(), ws2_plain);
        assert_eq!(&*archive.open_entry_raw(&entries[0]).unwrap(), &ws2_stored);
        assert_eq!(&*archive.open_entry(&entries[1]).unwrap(), b"ABC");
        assert!(archive.open_entry(&entries[2]).is_err());
        assert_eq!(&*archive.open_entry(&entries[3]).unwrap(), b"raw");

        let model_path = dir.0.join("CharaModel.arc");
        fs::write(&model_path, &bytes).unwrap();
        let model_arc = WillV2Arc
            .open(
                &Arc::new(ArcView::open(&model_path).unwrap()),
                &ArchiveOptions::default(),
            )
            .unwrap();
        assert_eq!(
            &*model_arc.open_entry(&model_arc.entries()[0]).unwrap(),
            &ws2_stored
        );

        let truncated_path = dir.0.join("truncated.arc");
        fs::write(&truncated_path, &bytes[..12]).unwrap();
        assert!(
            WillV2Arc
                .open(
                    &Arc::new(ArcView::open(&truncated_path).unwrap()),
                    &ArchiveOptions::default(),
                )
                .is_err()
        );
    }
}
