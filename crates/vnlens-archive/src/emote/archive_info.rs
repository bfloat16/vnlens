//! Emote/M2 archive-info PSB paired with a sibling body file.
//!
//! The info file is a PSB or MDF-wrapped PSB that contains `file_info` or
//! `umd_root` ranges. The raw payload bytes live in a sibling body file such as
//! `<package>_body.bin`, `<package>body.bin`, or `<package>.bin`.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use vnlens_core::{
    ArcView, Archive, ArchiveFormat, Entry, Error, Format, ResourceKind, Result, register_archive,
};
use vnlens_middleware::mdf;
use vnlens_middleware::psb::{self, ArchiveInfoEntry};

const SIGNATURES: &[u32] = &[0x0042_5350, 0x0066_646d, 0x0073_7a6d, 0x005a_5350];

/// Emote archive-info PSB format.
#[derive(Debug, Default)]
struct EmoteArchiveInfo;

impl Format for EmoteArchiveInfo {
    fn tag(&self) -> &'static str {
        "psb/archive-info"
    }

    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["psb", "m", "mdf", "mzs", "psz"]
    }

    fn description(&self) -> &'static str {
        "Emote/M2 archive-info PSB with sibling body.bin"
    }
}

impl ArchiveFormat for EmoteArchiveInfo {
    fn open(
        &self,
        view: &Arc<ArcView>,
        options: &vnlens_core::ArchiveOptions,
    ) -> Result<Box<dyn Archive>> {
        let mdf_base_key = options
            .keys
            .get("mdf_base")
            .map(|key| std::str::from_utf8(key.bytes()).map(str::to_owned))
            .transpose()
            .map_err(|_| Error::UnknownScheme(Some("Invalid MDF base key encoding".into())))?;
        let mdf_key_len = options
            .numbers
            .get("mdf_length")
            .map(|&n| {
                usize::try_from(n)
                    .map_err(|_| Error::Unsupported("MDF key length exceeds address space".into()))
            })
            .transpose()?;
        let info = psb::PsbFile::open_configured(view.clone(), view.file_name(), options, None)?;
        let (_, info_entries) = psb::archive_info_entries(&info.document)?;
        let body_path = find_body_path(view).ok_or_else(|| {
            Error::Unsupported("missing sibling body.bin for Emote archive-info PSB".to_string())
        })?;
        let mut entries = build_entries(&info_entries, view.related_len(&body_path)?)?;
        let suffix = psb::archive_info_suffix(&info.document).map(str::to_string);
        let kaleido = options.numbers.get("kaleido") == Some(&1);
        if kaleido {
            for entry in &mut entries {
                let name = logical_name(&entry.name, suffix.as_deref().unwrap_or(""));
                entry.kind = if name.ends_with(".nut") || name.ends_with(".scn") {
                    ResourceKind::Script
                } else if name.ends_with(".psb") {
                    ResourceKind::Data
                } else if name.ends_with(".otf") || name.ends_with(".ttf") {
                    ResourceKind::Font
                } else {
                    ResourceKind::Unknown
                };
            }
        }

        let mut used: BTreeSet<_> = entries.iter().map(|entry| entry.name.clone()).collect();
        let mut index_entries = BTreeMap::new();
        for (index, entry) in info.entries().iter().enumerate() {
            let mut exposed = entry.clone();
            exposed.name = format!("index/{}", entry.name);
            while !used.insert(exposed.name.clone()) {
                exposed.name = format!("index/{}", exposed.name);
            }
            index_entries.insert(exposed.name.clone(), index);
            entries.push(exposed);
        }
        Ok(Box::new(EmoteArchive {
            info,
            index_entries,
            index: view.clone(),
            body_path,
            body: OnceLock::new(),
            entries,
            mdf_base_key,
            mdf_key_len,
            suffix,
            kaleido,
        }))
    }
}

struct EmoteArchive {
    info: psb::PsbFile,
    index_entries: BTreeMap<String, usize>,
    index: Arc<ArcView>,
    body_path: PathBuf,
    body: OnceLock<ArcView>,
    entries: Vec<Entry>,
    mdf_base_key: Option<String>,
    mdf_key_len: Option<usize>,
    suffix: Option<String>,
    kaleido: bool,
}

impl std::fmt::Debug for EmoteArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmoteArchive")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl Archive for EmoteArchive {
    fn metadata(&self) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        self.info.metadata()
    }
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn entry_metadata(
        &self,
        entry: &Entry,
    ) -> Result<Option<Arc<dyn std::any::Any + Send + Sync>>> {
        match self.info_entry(entry) {
            Some(entry) => self.info.entry_metadata(entry),
            None => Ok(None),
        }
    }

    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        if let Some(entry) = self.info_entry(entry) {
            return self.info.open_entry(entry);
        }
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

    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn vnlens_io::ReadAt>>> {
        match self.info_entry(entry) {
            Some(entry) => self.info.open_entry_source(entry),
            None => Ok(None),
        }
    }

    fn virtual_paths(&self) -> Result<Vec<(usize, String)>> {
        if !self.kaleido {
            return Ok(Vec::new());
        }
        Ok(self
            .entries
            .iter()
            .take(self.entries.len() - self.info.entries().len())
            .enumerate()
            .map(|(i, entry)| {
                (
                    i,
                    logical_name(&entry.name, self.suffix.as_deref().unwrap_or("")),
                )
            })
            .collect())
    }

    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        if let Some(entry) = self.info_entry(entry) {
            return self.info.open_entry_raw(entry);
        }
        Ok(Cow::Borrowed(
            self.body_view()?.slice(entry.offset, entry.size)?,
        ))
    }
}

impl EmoteArchive {
    fn info_entry(&self, entry: &Entry) -> Option<&Entry> {
        self.index_entries
            .get(&entry.name)
            .map(|&index| &self.info.entries()[index])
    }
    fn body_view(&self) -> Result<&ArcView> {
        if let Some(view) = self.body.get() {
            return Ok(view);
        }
        let view = self.index.open_related(&self.body_path)?;
        let _ = self.body.set(view);
        self.body
            .get()
            .ok_or_else(|| Error::Unsupported("body view initialization failed".into()))
    }
}

fn decode_entry_mdf(
    raw: &[u8],
    entry_name: &str,
    suffix: &str,
    mdf_base_key: Option<&str>,
    key_len: Option<usize>,
) -> Result<Vec<u8>> {
    if let Some(base_key) = mdf_base_key {
        for file_name in psb::archive_info_possible_file_names(entry_name, suffix) {
            let key = format!("{base_key}{file_name}");
            match mdf::decode(raw, Some(mdf::MdfKey { key: &key, key_len })) {
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
            kind: ResourceKind::Unknown,
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

fn find_body_path(view: &ArcView) -> Option<PathBuf> {
    let info_path = view.path();
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
        .find(|candidate| view.related_len(candidate).is_ok())
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
#[path = "../../tests/emote/archive_info.rs"]
mod tests;

fn logical_name(name: &str, suffix: &str) -> String {
    if let Some(name) = name.strip_suffix(".m") {
        return name.to_owned();
    }
    let suffix = suffix.strip_suffix(".m").unwrap_or(suffix);
    if !name.contains('.') || (name.ends_with(".ks") && suffix == ".scn") {
        format!("{name}{suffix}")
    } else {
        name.to_owned()
    }
}
