//! Emote/M2 archive-info PSB paired with a sibling body file.
//!
//! The info file is a PSB or MDF-wrapped PSB that contains `file_info` or
//! `umd_root` ranges. The raw payload bytes live in a sibling body file such as
//! `<package>_body.bin`, `<package>body.bin`, or `<package>.bin`.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use nvlens_core::{
    ArcView, Archive, ArchiveFormat, Entry, Error, Format, ResourceKind, Result, register_archive,
};
use nvlens_script::mdf;
use nvlens_script::psb::{self, ArchiveInfoEntry, ParseOptions};

const SIGNATURES: &[u32] = &[0x0042_5350, 0x0066_646D];
const DEFAULT_MDF_KEY_LEN: usize = 0x83;

/// Emote archive-info PSB format.
#[derive(Debug, Default)]
struct EmoteArchiveInfo;

impl Format for EmoteArchiveInfo {
    fn tag(&self) -> &'static str {
        "psb/emote-archive-info"
    }

    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["psb", "m"]
    }

    fn description(&self) -> &'static str {
        "Emote/M2 archive-info PSB with sibling body.bin"
    }
}

impl ArchiveFormat for EmoteArchiveInfo {
    fn open(
        &self,
        view: &Arc<ArcView>,
        options: &nvlens_core::ArchiveOptions,
    ) -> Result<Box<dyn Archive>> {
        let mdf_base_key = options
            .keys
            .get("mdf_base")
            .map(|key| std::str::from_utf8(key.bytes()).map(str::to_owned))
            .transpose()
            .map_err(|_| Error::UnknownScheme(Some("Invalid MDF base key encoding".into())))?;
        let mdf_key_len = usize::try_from(
            *options
                .numbers
                .get("mdf_length")
                .unwrap_or(&(DEFAULT_MDF_KEY_LEN as u64)),
        )
        .map_err(|_| Error::Unsupported("MDF key length exceeds address space".into()))?;
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
        let parsed = parse_info_psb(view, mdf_base_key.as_deref(), mdf_key_len, psb_key)?;
        let (_, info_entries) = psb::archive_info_entries(&parsed)?;
        let body_path = find_body_path(view.path()).ok_or_else(|| {
            Error::Unsupported("missing sibling body.bin for Emote archive-info PSB".to_string())
        })?;
        let entries = build_entries(&info_entries, std::fs::metadata(&body_path)?.len())?;
        let suffix = psb::archive_info_suffix(&parsed).map(str::to_string);

        Ok(Box::new(EmoteArchive {
            body_path,
            body: OnceLock::new(),
            entries,
            mdf_base_key,
            mdf_key_len,
            suffix,
        }))
    }
}

struct EmoteArchive {
    body_path: PathBuf,
    body: OnceLock<ArcView>,
    entries: Vec<Entry>,
    mdf_base_key: Option<String>,
    mdf_key_len: usize,
    suffix: Option<String>,
}

impl std::fmt::Debug for EmoteArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmoteArchive")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl Archive for EmoteArchive {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let raw = self.body_view()?.slice(entry.offset, entry.size)?;
        if mdf::is_mdf(raw) {
            return Ok(Cow::Owned(decode_entry_mdf(
                raw,
                &entry.name,
                self.suffix.as_deref().unwrap_or(""),
                self.mdf_base_key.as_deref(),
                self.mdf_key_len,
            )?));
        }
        Ok(Cow::Borrowed(raw))
    }

    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(
            self.body_view()?.slice(entry.offset, entry.size)?,
        ))
    }
}

impl EmoteArchive {
    fn body_view(&self) -> Result<&ArcView> {
        if let Some(view) = self.body.get() {
            return Ok(view);
        }
        let view = ArcView::open(&self.body_path)?;
        let _ = self.body.set(view);
        self.body
            .get()
            .ok_or_else(|| Error::Unsupported("body view initialization failed".into()))
    }
}

fn parse_info_psb(
    view: &Arc<ArcView>,
    base_key: Option<&str>,
    key_len: usize,
    psb_key: Option<u32>,
) -> Result<psb::Psb> {
    let key = base_key.map(|base| format!("{base}{}", view.file_name()));
    let source = psb::open_source(
        Arc::clone(view),
        ParseOptions {
            psb_key,
            mdf_key: key.as_deref().map(|key| mdf::MdfKey {
                key,
                key_len: Some(key_len),
            }),
        },
    )?;
    psb::parse_source(&*source, psb_key)
}

fn decode_entry_mdf(
    raw: &[u8],
    entry_name: &str,
    suffix: &str,
    mdf_base_key: Option<&str>,
    key_len: usize,
) -> Result<Vec<u8>> {
    if let Some(base_key) = mdf_base_key {
        for file_name in psb::archive_info_possible_file_names(entry_name, suffix) {
            let key = format!("{base_key}{file_name}");
            match mdf::decode(
                raw,
                Some(mdf::MdfKey {
                    key: &key,
                    key_len: Some(key_len),
                }),
            ) {
                Ok(data) => return Ok(data),
                Err(Error::Corrupt { .. }) => continue,
                Err(e) => return Err(e),
            }
        }
    }
    mdf::decode(raw, None)
}

fn build_entries(info_entries: &[ArchiveInfoEntry], body_len: u64) -> Result<Vec<Entry>> {
    let mut entries = Vec::with_capacity(info_entries.len());
    for item in info_entries {
        let entry = Entry {
            name: item.name.clone(),
            kind: ResourceKind::guess_from_name(&item.name),
            offset: item.offset,
            size: item.size,
            packed: None,
        };
        if !entry.check_placement(body_len) {
            return Err(Error::Corrupt {
                offset: item.offset,
                reason: "archive-info entry range is out of body bounds".to_string(),
            });
        }
        entries.push(entry);
    }
    Ok(entries)
}

fn find_body_path(info_path: &Path) -> Option<PathBuf> {
    let dir = info_path.parent()?;
    let name = package_name_from_info(info_path.file_name()?.to_str()?);
    let candidates = [
        format!("{name}_body.bin"),
        format!("{name}body.bin"),
        format!("{name}.bin"),
    ];
    candidates
        .iter()
        .map(|candidate| dir.join(candidate))
        .find(|candidate| candidate.is_file())
}

fn package_name_from_info(file_name: &str) -> String {
    if let Some(pos) = file_name.find("_info.") {
        return file_name[..pos].to_string();
    }
    if let Some(pos) = file_name.find('.') {
        return file_name[..pos].to_string();
    }
    String::new()
}

register_archive!(EmoteArchiveInfo);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use nvlens_core::Catalog;
    use nvlens_io::BinaryWriter;

    use super::*;

    #[test]
    fn package_name_matches_freemote_rules() {
        assert_eq!(package_name_from_info("sample_info.psb.m"), "sample");
        assert_eq!(package_name_from_info("sampleinfo.psb.m"), "sampleinfo");
    }

    #[test]
    fn preserves_names_for_output_layer_mapping() {
        let entries = [ArchiveInfoEntry {
            name: "../bad.bin".to_string(),
            offset: 0,
            size: 1,
        }];
        assert_eq!(
            build_entries(&entries, 10).unwrap()[0].name,
            entries[0].name
        );
    }

    #[test]
    fn rejects_out_of_range_entries() {
        let entries = [ArchiveInfoEntry {
            name: "ok.bin".to_string(),
            offset: 8,
            size: 4,
        }];
        assert!(build_entries(&entries, 10).is_err());
    }

    #[test]
    fn catalog_opens_info_psb_with_sibling_body() {
        crate::init();
        let dir = unique_temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let info_path = dir.join("sample_info.psb.m");
        let body_path = dir.join("sample_body.bin");
        let info = minimal_archive_info_psb();
        let parsed = psb::parse_source(&info.as_slice(), None).unwrap();
        let (_, parsed_entries) = psb::archive_info_entries(&parsed).unwrap();
        assert_eq!(parsed_entries[0].name, "dir/file.bin");
        fs::write(&info_path, info).unwrap();
        fs::write(&body_path, b"abcdef").unwrap();

        let catalog = Catalog::load();
        let opened = catalog
            .open(
                &info_path,
                &nvlens_core::ArchiveRoute::new("psb/emote-archive-info"),
            )
            .unwrap();
        assert_eq!(opened.format_tag, "psb/emote-archive-info");
        let entries = opened.archive.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "dir/file.bin");
        assert_eq!(entries[0].offset, 1);
        // A mapped body would prevent replacement on Windows. Mounting must
        // leave it unopened until an entry is actually requested.
        fs::rename(&body_path, dir.join("unused_body.bin")).unwrap();
        fs::write(&body_path, b"ABCDEF").unwrap();
        assert_eq!(
            opened.archive.open_entry_raw(&entries[0]).unwrap().as_ref(),
            b"BCD"
        );
        assert_eq!(
            opened.archive.open_entry(&entries[0]).unwrap().as_ref(),
            b"BCD"
        );
        drop(opened);
        fs::remove_dir_all(&dir).unwrap();
    }

    fn minimal_archive_info_psb() -> Vec<u8> {
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

        let names = ["file_info", "dir/file.bin"];
        let (charset, names_data, name_indexes) = build_names(&names);

        let offset_names = out.len();
        push_array(&mut out, &charset);
        push_array(&mut out, &names_data);
        push_array(&mut out, &name_indexes);

        let offset_strings = out.len();
        push_array(&mut out, &[]);

        let offset_strings_data = out.len();
        out.push(0);

        let offset_chunk_offsets = out.len();
        push_array(&mut out, &[]);

        let offset_chunk_lengths = out.len();
        push_array(&mut out, &[]);

        let offset_chunk_data = out.len();

        let offset_entries = out.len();
        push_object(&mut out, &[0], &[0], |out| {
            push_object(out, &[1], &[0], |out| {
                push_list(out, &[0, 2], |out| {
                    push_number(out, 1);
                    push_number(out, 3);
                });
            });
        });

        patch_u32(&mut out, offset_names_pos, offset_names);
        patch_u32(&mut out, offset_strings_pos, offset_strings);
        patch_u32(&mut out, offset_strings_data_pos, offset_strings_data);
        patch_u32(&mut out, offset_chunk_offsets_pos, offset_chunk_offsets);
        patch_u32(&mut out, offset_chunk_lengths_pos, offset_chunk_lengths);
        patch_u32(&mut out, offset_chunk_data_pos, offset_chunk_data);
        patch_u32(&mut out, offset_entries_pos, offset_entries);
        out
    }

    fn build_names(names: &[&str]) -> (Vec<u32>, Vec<u32>, Vec<u32>) {
        let mut charset = vec![0; 512];
        let mut names_data = vec![0; 512];
        let mut indexes = Vec::with_capacity(names.len());
        let mut next_node = 256u32;

        for name in names {
            let mut code = 0u32;
            for &byte in name.as_bytes() {
                let byte = u32::from(byte);
                let chr = if code == 0 {
                    byte
                } else {
                    let value = next_node;
                    next_node += 1;
                    value
                };
                ensure_len(&mut charset, code);
                ensure_len(&mut names_data, chr);
                charset[usize::try_from(code).unwrap()] = chr.checked_sub(byte).unwrap();
                names_data[usize::try_from(chr).unwrap()] = code;
                code = chr;
            }
            let index = next_node;
            next_node += 1;
            ensure_len(&mut names_data, index);
            names_data[usize::try_from(index).unwrap()] = code;
            indexes.push(index);
        }

        (charset, names_data, indexes)
    }

    fn ensure_len(values: &mut Vec<u32>, index: u32) {
        let len = usize::try_from(index).unwrap() + 1;
        if values.len() < len {
            values.resize(len, 0);
        }
    }

    fn push_object(
        out: &mut Vec<u8>,
        name_indexes: &[u32],
        offsets: &[u32],
        body: impl FnOnce(&mut Vec<u8>),
    ) {
        out.push(0x21);
        push_array(out, name_indexes);
        push_array(out, offsets);
        body(out);
    }

    fn push_list(out: &mut Vec<u8>, offsets: &[u32], body: impl FnOnce(&mut Vec<u8>)) {
        out.push(0x20);
        push_array(out, offsets);
        body(out);
    }

    fn push_number(out: &mut Vec<u8>, value: u8) {
        out.push(0x05);
        out.push(value);
    }

    fn push_array(out: &mut Vec<u8>, values: &[u32]) {
        let count_width = compact_width(u32::try_from(values.len()).unwrap());
        let entry_width = values.iter().copied().max().map_or(1, compact_width);
        out.push(0x0C + count_width);
        let mut count = [0u8; 4];
        BinaryWriter::u32_le(u32::try_from(values.len()).unwrap(), &mut count);
        out.extend_from_slice(&count[..usize::from(count_width)]);
        out.push(0x0C + entry_width);
        for &value in values {
            let mut bytes = [0u8; 4];
            BinaryWriter::u32_le(value, &mut bytes);
            out.extend_from_slice(&bytes[..usize::from(entry_width)]);
        }
    }

    fn compact_width(value: u32) -> u8 {
        if value > u32::from(u8::MAX) { 2 } else { 1 }
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

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("nvlens-archive-info-test-{nanos}"))
    }
}
