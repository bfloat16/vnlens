//! Standalone Emote/M2 PSB embedded resource chunks (`PSB\0` or MDF-wrapped `mdf\0`).
//!
//! Layout (all little-endian):
//! - PSB header and index arrays (`offset_chunk_offsets`, `offset_chunk_lengths`,
//!   `offset_chunk_data`, plus v4 `extra` chunk tables) parsed via [`vnlens_script::psb`].
//! - Each resource chunk is exposed as `resources/NNNN.bin` or `extra/NNNN.bin`
//!   backed lazily by the mapped file or streaming MDF source.
//! - Archive-info PSBs (`file_info` / `umd_root`) are rejected here and handled
//!   by [`super::archive_info::EmoteArchiveInfo`].

use std::borrow::Cow;
use std::sync::Arc;

use vnlens_core::{
    ArcView, Archive, ArchiveFormat, Entry, Error, Format, ResourceKind, Result, register_archive,
};
use vnlens_io::ReadAt;
use vnlens_script::psb::{self, ParseOptions, Psb};

const SIGNATURES: &[u32] = &[0x0042_5350, 0x0066_646d, 0x0073_7a6d];

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
        options: &vnlens_core::ArchiveOptions,
    ) -> Result<Box<dyn Archive>> {
        let psb_key = options
            .keys
            .get("psb")
            .map(|key| {
                if key.bytes().len() != 4 {
                    return Err(Error::UnknownScheme(Some("Invalid PSB key".into())));
                }
                Ok(vnlens_io::BinaryReader::u32_le(key.bytes()))
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
                mdf_key: mdf_key.as_deref().map(|key| vnlens_script::mdf::MdfKey {
                    key,
                    key_len: mdf_key_len,
                }),
            },
        )?;
        from_source(source, psb_key)
    }
}

pub(super) fn from_source(
    source: Arc<dyn ReadAt>,
    psb_key: Option<u32>,
) -> Result<Box<dyn Archive>> {
    let parsed = psb::parse_source(&*source, psb_key)?;
    match psb::archive_info_entries(&parsed) {
        Ok(_) => return Err(Error::InvalidFormat),
        Err(Error::InvalidFormat) => {}
        Err(error) => return Err(error),
    }
    let media = super::media::encodings(&parsed)?;
    let mut entries = build_entries(&parsed)?;
    let mut encodings = Vec::new();
    for (entry, resource) in entries
        .iter_mut()
        .zip(parsed.resources.iter().chain(&parsed.extra_resources))
    {
        let encoding = media.get(&(resource.index, resource.is_extra)).cloned();
        if let Some(encoding) = &encoding {
            entry.name =
                entry.name.trim_end_matches(".bin").to_owned() + "." + encoding.extension();
            entry.kind = match encoding {
                super::media::Encoding::Bc7 { .. } | super::media::Encoding::Canvas(_) => {
                    ResourceKind::Image
                }
                super::media::Encoding::Xwma { .. } => ResourceKind::Audio,
            };
        }
        encodings.push(encoding);
    }
    for (entry, canvas) in super::media::canvases(&parsed)? {
        entries.push(entry);
        encodings.push(Some(super::media::Encoding::Canvas(canvas)));
    }
    Ok(Box::new(PsbResourceArchive {
        source,
        entries,
        encodings,
    }))
}

struct PsbResourceArchive {
    source: Arc<dyn ReadAt>,
    entries: Vec<Entry>,
    encodings: Vec<Option<super::media::Encoding>>,
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
        let index = self
            .entries
            .iter()
            .position(|stored| stored.name == entry.name)
            .ok_or(Error::InvalidFormat)?;
        if let Some(encoding @ super::media::Encoding::Canvas(_)) = &self.encodings[index] {
            return encoding.wrap(&*self.source, &[]).map(Cow::Owned);
        }
        let raw = self.source.read_at(entry.offset, size)?;
        if let Some(encoding) = &self.encodings[index] {
            return encoding.wrap(&*self.source, &raw).map(Cow::Owned);
        }
        Ok(raw)
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let size = usize::try_from(entry.size)
            .map_err(|_| Error::Unsupported("PSB chunk exceeds address space".into()))?;
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
