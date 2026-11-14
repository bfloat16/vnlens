//! CNMT-associated base/update selection for sibling NS packages. On-disk
//! records follow Atmosphere ncm::PackagedContentMetaHeader,
//! PatchMetaExtendedHeader and PackagedContentInfo. Application IDs, numeric
//! versions, content types and ID offsets select updates, never filenames.
use super::{corrupt, nca::Nca, open_partition, open_xci};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use vnlens_core::{Error, Result};
use vnlens_io::{ArcView, BinaryReader, ReadAt};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Content {
    id: String,
    kind: u8,
    index: u8,
    size: u64,
}
#[derive(Debug)]
struct Meta {
    source: String,
    application: u64,
    version: u32,
    patch: bool,
    contents: Vec<Content>,
}
impl Meta {
    fn content(&self, kind: u8, index: u8) -> Option<&Content> {
        self.contents
            .iter()
            .find(|content| content.kind == kind && content.index == index)
    }
}
pub(super) struct Catalog {
    ncas: BTreeMap<String, Arc<Nca>>,
    metadata: Vec<Meta>,
    packages: BTreeMap<PathBuf, Vec<String>>,
    unavailable: BTreeMap<String, Arc<dyn ReadAt>>,
}

impl Catalog {
    pub fn load(directory: &Path, cancelled: &std::sync::atomic::AtomicBool) -> Result<Self> {
        let mut catalog = Self {
            ncas: BTreeMap::new(),
            metadata: Vec::new(),
            packages: BTreeMap::new(),
            unavailable: BTreeMap::new(),
        };
        let mut tickets = Vec::new();
        let mut paths = std::fs::read_dir(directory)?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        paths.sort();
        for path in paths {
            super::check_cancel(cancelled)?;
            let Some(extension) = path.extension().and_then(|s| s.to_str()) else {
                continue;
            };
            let kind = extension.to_ascii_lowercase();
            if !matches!(kind.as_str(), "nsp" | "xci" | "nca" | "pfs0" | "hfs0") || !path.is_file()
            {
                continue;
            }
            let source: Arc<dyn ReadAt> = Arc::new(ArcView::open(&path)?);
            if kind == "nca" {
                let name = catalog.insert(
                    path.file_name().and_then(|s| s.to_str()).unwrap_or(""),
                    source,
                )?;
                catalog.packages.entry(path).or_default().push(name);
                continue;
            }
            let mut pending = vec![(source, kind)];
            while let Some((source, kind)) = pending.pop() {
                super::check_cancel(cancelled)?;
                let fs = match kind.as_str() {
                    "xci" => open_xci(source)?,
                    "hfs0" => open_partition(source, true)?,
                    _ => open_partition(source, false)?,
                };
                for entry in &fs.entries {
                    super::check_cancel(cancelled)?;
                    if kind == "xci" {
                        // Firmware update partitions are independent titles,
                        // not application updates. Only the secure game bank
                        // participates in this application's content catalog.
                        if entry.name == "secure" {
                            pending.push((fs.source(entry)?, "hfs0".into()));
                        }
                    } else if entry.name.to_ascii_lowercase().ends_with(".nca") {
                        let name = catalog.insert(&entry.name, fs.source(entry)?)?;
                        catalog.packages.entry(path.clone()).or_default().push(name);
                    } else if entry.name.to_ascii_lowercase().ends_with(".tik") {
                        tickets.push(fs.source(entry)?);
                    } else if entry.name.to_ascii_lowercase().ends_with(".pfs0") {
                        pending.push((fs.source(entry)?, "pfs0".into()));
                    }
                }
            }
        }
        if !tickets.is_empty() {
            let mut keys = catalog
                .ncas
                .values()
                .find_map(|nca| nca.keys())
                .map(|keys| keys.as_ref().clone())
                .unwrap_or_default();
            for ticket in tickets {
                super::check_cancel(cancelled)?;
                keys.ticket(ticket.as_ref())?;
            }
            let keys = Arc::new(keys);
            for nca in catalog.ncas.values_mut() {
                Arc::get_mut(nca)
                    .ok_or_else(|| corrupt(0, "NCA metadata was shared before ticket import"))?
                    .set_keys(keys.clone());
            }
        }
        for (name, nca) in catalog
            .ncas
            .iter()
            .filter(|(_, nca)| nca.content_type() == 1)
        {
            for entry in nca
                .entries
                .iter()
                .filter(|entry| entry.name.ends_with(".pfs0"))
            {
                let fs = open_partition(nca.source(entry, cancelled)?, false)?;
                for meta in fs
                    .entries
                    .iter()
                    .filter(|entry| entry.name.ends_with(".cnmt"))
                {
                    let bytes = fs.read(meta)?;
                    if let Some(mut meta) = parse(&bytes)? {
                        meta.source = name.clone();
                        catalog.metadata.push(meta);
                    }
                }
            }
        }
        // A damaged, unreferenced content header must not prevent browsing a
        // sibling package. Revisit deferred failures only when CNMT needs it.
        for content in catalog.metadata.iter().flat_map(|meta| &meta.contents) {
            if let Some(source) = catalog.unavailable.get(&content.id) {
                super::check_cancel(cancelled)?;
                Nca::open(source.clone())?;
            }
        }
        Ok(catalog)
    }
    fn insert(&mut self, name: &str, source: Arc<dyn ReadAt>) -> Result<String> {
        let name = name
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(name)
            .to_ascii_lowercase();
        let nca = match Nca::open(source.clone()) {
            Ok(nca) => Arc::new(nca),
            Err(error) if name.ends_with(".cnmt.nca") => return Err(error),
            Err(_) => {
                self.unavailable.insert(name.clone(), source);
                return Ok(name);
            }
        };
        if let Some(previous) = self.ncas.get(&name) {
            if previous.identity() != nca.identity() {
                return Err(corrupt(
                    0,
                    "Conflicting NCA content IDs in sibling packages",
                ));
            }
        } else {
            self.ncas.insert(name.clone(), nca);
        }
        Ok(name)
    }
    pub fn application_paths(
        &self,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<BTreeMap<PathBuf, PathBuf>> {
        let mut result = BTreeMap::new();
        for (path, names) in &self.packages {
            super::check_cancel(cancelled)?;
            let mut base_path = None;
            for meta in self
                .metadata
                .iter()
                .filter(|meta| names.contains(&meta.source))
            {
                super::check_cancel(cancelled)?;
                let Some(base) = self.latest(meta.application, false)? else {
                    continue;
                };
                let Some((base, _)) = self
                    .packages
                    .iter()
                    .find(|(_, contents)| contents.contains(&base.source))
                else {
                    continue;
                };
                if base_path.is_some_and(|previous| previous != base) {
                    // A package carrying multiple independent applications
                    // keeps its own identity instead of choosing one title.
                    base_path = None;
                    break;
                }
                base_path = Some(base);
            }
            if let Some(base) = base_path {
                result.insert(path.clone(), base.clone());
            }
        }
        Ok(result)
    }
    pub fn resolve(
        &self,
        name: &str,
        header: &[u8],
        section: usize,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<Option<Arc<dyn ReadAt>>> {
        super::check_cancel(cancelled)?;
        let mut selected = None;
        for meta in &self.metadata {
            super::check_cancel(cancelled)?;
            for content in meta.contents.iter().filter(|content| content.id == name) {
                let key = (meta.application, content.kind, content.index);
                if selected.is_some_and(|previous| previous != key) {
                    return Err(corrupt(
                        0,
                        "Ambiguous CNMT association for selected content",
                    ));
                }
                selected = Some(key);
            }
        }
        let Some((application, kind, index)) = selected else {
            return Ok(None);
        };
        let original = self.latest(application, false)?;
        let update = self
            .latest(application, true)?
            .filter(|update| original.is_none_or(|base| update.version >= base.version));
        let original = original
            .and_then(|meta| meta.content(kind, index))
            .map(|content| self.content(content))
            .transpose()?;
        let Some(updated) = update.and_then(|meta| meta.content(kind, index)) else {
            return Ok(None);
        };
        let updated = self.content(updated)?;
        let current = self
            .ncas
            .get(name)
            .ok_or_else(|| corrupt(0, "Selected NCA is absent from sibling catalog"))?;
        if current.identity() != header {
            return Err(corrupt(0, "Selected NCA differs from sibling catalog"));
        }
        let effective = if updated.has_section(section) {
            updated
        } else {
            original.ok_or_else(|| {
                Error::Unsupported("NCA filesystem section is absent in associated content".into())
            })?
        };
        Ok(Some(effective.source_with_base(
            section,
            original.map(Arc::as_ref),
            cancelled,
        )?))
    }
    fn content(&self, content: &Content) -> Result<&Arc<Nca>> {
        let nca = self.ncas.get(&content.id).ok_or_else(|| {
            Error::Unsupported(format!(
                "CNMT references missing NCA content {}",
                content.id
            ))
        })?;
        if BinaryReader::u64_le(&nca.identity()[0x208..]) != content.size {
            return Err(corrupt(0, "CNMT content size differs from NCA header"));
        }
        Ok(nca)
    }
    fn latest(&self, application: u64, patch: bool) -> Result<Option<&Meta>> {
        let mut selected: Option<&Meta> = None;
        for meta in self
            .metadata
            .iter()
            .filter(|meta| meta.application == application && meta.patch == patch)
        {
            match selected {
                Some(previous)
                    if meta.version == previous.version && meta.contents != previous.contents =>
                {
                    return Err(corrupt(
                        0,
                        "Conflicting CNMT records for the same application version",
                    ));
                }
                Some(previous) if previous.version >= meta.version => {}
                _ => selected = Some(meta),
            }
        }
        Ok(selected)
    }
}

fn parse(bytes: &[u8]) -> Result<Option<Meta>> {
    let mut reader = BinaryReader::new(bytes);
    let header = reader.read_bytes(0x20)?;
    let kind = header[12];
    if !matches!(kind, 0x80 | 0x81) {
        return Ok(None);
    }
    let size = usize::from(BinaryReader::u16_le(&header[14..]));
    let extended = reader.read_bytes(size)?;
    if size < if kind == 0x80 { 0x10 } else { 0x18 } {
        return Err(corrupt(14, "CNMT extended header is truncated"));
    }
    let count = usize::from(BinaryReader::u16_le(&header[16..]));
    let records = reader.read_bytes(count * 0x38)?;
    // Related meta records are part of the declared index, even when their
    // titles do not participate in this application update.
    reader.read_bytes(usize::from(BinaryReader::u16_le(&header[18..])) * 16)?;
    let mut contents = Vec::new();
    for record in records.as_chunks::<0x38>().0 {
        let id = record[32..48]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            + ".nca";
        let mut size = [0; 8];
        size[..5].copy_from_slice(&record[48..53]);
        contents.push(Content {
            id,
            kind: record[54],
            index: record[55],
            size: BinaryReader::u64_le(&size),
        });
    }
    Ok(Some(Meta {
        source: String::new(),
        application: BinaryReader::u64_le(if kind == 0x80 { header } else { extended }),
        version: BinaryReader::u32_le(&header[8..]),
        patch: kind == 0x81,
        contents,
    }))
}

#[cfg(test)]
#[path = "../../tests/ns/package.rs"]
mod tests;
