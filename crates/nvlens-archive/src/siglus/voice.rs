//! OVK/NWK: LE count followed by (size, absolute offset, voice ID [, duration])
//! records. Payloads are independent Ogg Vorbis or NWA streams. The index's
//! voice IDs, rather than physical ordering, form the exported resource names.
use nvlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, ResourceKind, Result,
};
use nvlens_io::{ArcView, BinaryReader};
use std::{borrow::Cow, sync::Arc};
#[derive(Debug, Default)]
struct VoiceFormat;
impl Format for VoiceFormat {
    fn tag(&self) -> &'static str {
        "voice/siglus"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["ovk", "nwk"]
    }
    fn description(&self) -> &'static str {
        "SiglusEngine OVK/NWK voice archive"
    }
}
impl ArchiveFormat for VoiceFormat {
    fn open(&self, view: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        let nwa = view
            .path()
            .extension()
            .is_some_and(|s| s.eq_ignore_ascii_case("nwk"));
        let record = if nwa { 12 } else { 16 };
        let extension = if nwa { "nwa" } else { "ogg" };
        let stem = view
            .path()
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy();
        let count = BinaryReader::new(view.slice(0, 4)?).read_u32_le()?;
        let end = 4 + u64::from(count) * record;
        let mut r = BinaryReader::new(view.slice(4, end - 4)?);
        let mut entries = Vec::new();
        for _ in 0..count {
            let size = u64::from(r.read_u32_le()?);
            let offset = u64::from(r.read_u32_le()?);
            let id = r.read_u32_le()?;
            if !nwa {
                r.read_u32_le()?;
            }
            let entry = Entry {
                name: format!("{stem}#{id:05}.{extension}"),
                kind: ResourceKind::Audio,
                offset,
                size,
                packed: None,
            };
            if offset < end || !entry.check_placement(view.len()) {
                return Err(Error::Corrupt {
                    offset,
                    reason: "Siglus voice range overlaps index or exceeds file".into(),
                });
            }
            entries.push(entry);
        }
        Ok(Box::new(Voice {
            view: view.clone(),
            entries,
        }))
    }
}
#[derive(Debug)]
struct Voice {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
}
impl Archive for Voice {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
}
nvlens_core::register_archive!(VoiceFormat);
