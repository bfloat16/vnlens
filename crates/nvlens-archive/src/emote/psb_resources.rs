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
#[allow(clippy::unwrap_used)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use nvlens_core::Catalog;
    use nvlens_io::BinaryWriter;
    use nvlens_script::psb::{PsbResource, PsbValue};

    use super::*;

    #[test]
    fn builds_raw_resource_entries() {
        let psb = Psb {
            data_len: 3,
            names: Vec::new(),
            strings: Vec::new(),
            resources: vec![PsbResource {
                index: 0,
                is_extra: false,
                offset: 0,
                size: 3,
            }],
            extra_resources: Vec::new(),
            root: PsbValue::Null,
        };

        let entries = build_entries(&psb).unwrap();
        assert_eq!(entries[0].name, "resources/0000.bin");
        assert_eq!(entries[0].size, 3);
    }

    #[test]
    fn catalog_opens_standalone_psb_resources() {
        crate::init();
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let psb_path = dir.join("standalone.psb");
        fs::write(&psb_path, minimal_resource_psb()).unwrap();

        let catalog = Catalog::load();
        let opened = catalog
            .open(
                &psb_path,
                &nvlens_core::ArchiveRoute::new("psb/emote-resources"),
            )
            .unwrap();
        assert_eq!(opened.format_tag, "psb/emote-resources");
        assert_eq!(opened.archive.entries()[0].name, "resources/0000.bin");
        assert_eq!(
            opened
                .archive
                .open_entry_raw(&opened.archive.entries()[0])
                .unwrap()
                .as_ref(),
            b"res"
        );

        drop(opened);
        fs::remove_dir_all(&dir).unwrap();
    }

    fn minimal_resource_psb() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"PSB\0");
        push_u16(&mut out, 3);
        push_u16(&mut out, 0);
        push_u32(&mut out, 44);
        let offset_names_pos = out.len();
        push_u32(&mut out, 0);
        let offset_strings_pos = out.len();
        push_u32(&mut out, 0);
        let offset_strings_data_pos = out.len();
        push_u32(&mut out, 0);
        let offset_chunk_offsets_pos = out.len();
        push_u32(&mut out, 0);
        let offset_chunk_lengths_pos = out.len();
        push_u32(&mut out, 0);
        let offset_chunk_data_pos = out.len();
        push_u32(&mut out, 0);
        let offset_entries_pos = out.len();
        push_u32(&mut out, 0);
        push_u32(&mut out, 0);

        let offset_names = out.len();
        push_array(&mut out, &[0]);
        push_array(&mut out, &[0]);
        push_array(&mut out, &[]);

        let offset_strings = out.len();
        push_array(&mut out, &[]);

        let offset_strings_data = out.len();
        out.push(0);

        let offset_chunk_offsets = out.len();
        push_array(&mut out, &[0]);

        let offset_chunk_lengths = out.len();
        push_array(&mut out, &[3]);

        let offset_entries = out.len();
        out.push(0x01);

        let offset_chunk_data = out.len();
        out.extend_from_slice(b"res");

        patch_u32(&mut out, offset_names_pos, offset_names);
        patch_u32(&mut out, offset_strings_pos, offset_strings);
        patch_u32(&mut out, offset_strings_data_pos, offset_strings_data);
        patch_u32(&mut out, offset_chunk_offsets_pos, offset_chunk_offsets);
        patch_u32(&mut out, offset_chunk_lengths_pos, offset_chunk_lengths);
        patch_u32(&mut out, offset_chunk_data_pos, offset_chunk_data);
        patch_u32(&mut out, offset_entries_pos, offset_entries);
        out
    }

    fn push_array(out: &mut Vec<u8>, values: &[u32]) {
        out.push(0x0D);
        out.push(u8::try_from(values.len()).unwrap());
        out.push(0x0D);
        for &value in values {
            out.push(u8::try_from(value).unwrap());
        }
    }

    fn push_u16(out: &mut Vec<u8>, value: u16) {
        let mut bytes = [0u8; 2];
        BinaryWriter::u16_le(value, &mut bytes);
        out.extend_from_slice(&bytes);
    }

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        let mut bytes = [0u8; 4];
        BinaryWriter::u32_le(value, &mut bytes);
        out.extend_from_slice(&bytes);
    }

    fn patch_u32(out: &mut [u8], offset: usize, value: usize) {
        BinaryWriter::u32_le_at(u32::try_from(value).unwrap(), out, offset);
    }

    fn unique_temp_dir() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("nvlens-psb-resource-test-{nanos}"))
    }
}
