//! Standalone Emote/M2 PSB embedded resource chunks (`PSB\0` or MDF-wrapped `mdf\0`).
//!
//! Layout (all little-endian):
//! - PSB header and index arrays (`offset_chunk_offsets`, `offset_chunk_lengths`,
//!   `offset_chunk_data`, plus v4 `extra` chunk tables) parsed via [`nvlens_script::psb`].
//! - Each resource chunk is exposed as `resources/NNNN.bin` or `extra/NNNN.bin`
//!   backed lazily by the mapped file or streaming MDF source.
//! - Archive-info PSBs (`file_info` / `umd_root`) are rejected here and handled
//!   by [`super::archive_info::EmoteArchiveInfo`].

use std::borrow::Cow;
use std::sync::Arc;

use nvlens_core::{
    ArcView, Archive, ArchiveFormat, Entry, Error, Format, ResourceKind, Result, register_archive,
};
use nvlens_io::ReadAt;
use nvlens_script::psb::{self, ParseOptions, Psb};

const SIGNATURES: &[u32] = &[0x0042_5350, 0x0066_646D];

/// Standalone PSB resource-chunk archive view.
#[derive(Debug, Default)]
struct EmotePsbResources;

impl Format for EmotePsbResources {
    fn tag(&self) -> &'static str {
        "psb/emote-resources"
    }

    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["psb", "m"]
    }

    fn description(&self) -> &'static str {
        "Emote/M2 PSB embedded raw resource chunks"
    }
}

impl ArchiveFormat for EmotePsbResources {
    fn open(
        &self,
        view: &Arc<ArcView>,
        options: &nvlens_core::ArchiveOptions,
    ) -> Result<Box<dyn Archive>> {
        let psb_key = options
            .keys
            .get("psb")
            .map(|key| {
                if key.bytes().len() != 4 {
                    return Err(Error::UnknownScheme(Some("Invalid PSB key".into())));
                }
                Ok(nvlens_io::BinaryReader::u32_le(key.bytes()))
            })
            .transpose()?;
        let mdf_key = options
            .keys
            .get("mdf_base")
            .map(|key| std::str::from_utf8(key.bytes()))
            .transpose()
            .map_err(|_| Error::UnknownScheme(Some("Invalid MDF key".into())))?
            .map(|base| format!("{base}{}", view.file_name()));
        let mdf_key_len = options
            .numbers
            .get("mdf_length")
            .map(|&n| {
                usize::try_from(n)
                    .map_err(|_| Error::Unsupported("MDF key length exceeds address space".into()))
            })
            .transpose()?;
        let source = psb::open_source(
            Arc::clone(view),
            ParseOptions {
                psb_key,
                mdf_key: mdf_key.as_deref().map(|key| nvlens_script::mdf::MdfKey {
                    key,
                    key_len: mdf_key_len,
                }),
            },
        )?;
        let parsed = psb::parse_source(&*source, psb_key)?;
        match psb::archive_info_entries(&parsed) {
            Ok(_) => return Err(Error::InvalidFormat),
            Err(Error::InvalidFormat) => {}
            Err(error) => return Err(error),
        }
        let entries = build_entries(&parsed)?;
        Ok(Box::new(PsbResourceArchive { source, entries }))
    }
}

struct PsbResourceArchive {
    source: Arc<dyn ReadAt>,
    entries: Vec<Entry>,
}

impl std::fmt::Debug for PsbResourceArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PsbResourceArchive")
            .field("entries", &self.entries)
            .finish_non_exhaustive()
    }
}

impl Archive for PsbResourceArchive {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let size = usize::try_from(entry.size)
            .map_err(|_| Error::Unsupported("resource size does not fit address space".into()))?;
        Ok(self.source.read_at(entry.offset, size)?)
    }
}

fn build_entries(psb: &Psb) -> Result<Vec<Entry>> {
    let total = psb
        .resources
        .len()
        .checked_add(psb.extra_resources.len())
        .ok_or_else(|| Error::Corrupt {
            offset: 0,
            reason: "PSB resource count overflow".to_string(),
        })?;
    let mut entries = Vec::with_capacity(total);

    for resource in psb.resources.iter().chain(&psb.extra_resources) {
        let prefix = if resource.is_extra {
            "extra"
        } else {
            "resources"
        };
        let entry = Entry {
            name: format!("{prefix}/{:04}.bin", resource.index),
            kind: ResourceKind::Unknown,
            offset: resource.offset,
            size: resource.size,
            packed: None,
        };
        if !entry.check_placement(psb.data_len) {
            return Err(Error::Corrupt {
                offset: entry.offset,
                reason: "PSB resource range exceeds source".into(),
            });
        }
        entries.push(entry);
    }
    Ok(entries)
}

register_archive!(EmotePsbResources);

#[cfg(test)]
#[path = "../../tests/emote/psb_resources.rs"]
mod tests;
