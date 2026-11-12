//! Complete PSB container loading. Shell framing, stream decryption, object
//! metadata and resource transformations share one retained logical source.
//! Named root resources retain every declared alias; unnamed chunks remain
//! accessible by index. Serialized members are native virtual files alongside
//! binary resources. Mounting never reads resource payloads or writes JSON.
use super::{ParseOptions, Psb, PsbValue, check_cancelled, media};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use vnlens_core::{Archive, ArchiveOptions, Entry, Error, ResourceKind, Result};
use vnlens_io::{BinaryReader, RangeSource, ReadAt};

/// A parsed PSB and all its resources. The full document remains available
/// even for containers with no binary chunks or an application-specific tree.
pub struct PsbFile {
    pub document: Arc<Psb>,
    source: Arc<dyn ReadAt>,
    entries: Vec<Entry>,
    lookup: BTreeMap<String, usize>,
    contents: Vec<Content>,
}

enum Content {
    Resource(Option<media::Encoding>),
    Value(Option<String>),
}

impl std::fmt::Debug for PsbFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PsbFile")
            .field("document", &self.document)
            .field("entries", &self.entries)
            .finish_non_exhaustive()
    }
}

impl PsbFile {
    /// Applies caller-resolved PSB/MDF parameters. The logical filename supplies
    /// the MDF key suffix; no game identity or filesystem lookup is performed.
    pub fn open_configured(
        source: Arc<dyn ReadAt>,
        name: &str,
        options: &ArchiveOptions,
        cancelled: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<Self> {
        let psb_key = options
            .keys
            .get("psb")
            .map(|key| {
                if key.bytes().len() != 4 {
                    return Err(Error::UnknownScheme(Some("Invalid PSB key".into())));
                }
                Ok(BinaryReader::u32_le(key.bytes()))
            })
            .transpose()?;
        let mdf_key = options
            .keys
            .get("mdf_base")
            .map(|key| std::str::from_utf8(key.bytes()))
            .transpose()
            .map_err(|_| Error::UnknownScheme(Some("Invalid MDF key".into())))?
            .map(|base| format!("{base}{}", name.rsplit(['/', '\\']).next().unwrap_or(name)));
        let key_len = options
            .numbers
            .get("mdf_length")
            .map(|&n| {
                usize::try_from(n)
                    .map_err(|_| Error::Unsupported("MDF key length exceeds address space".into()))
            })
            .transpose()?;
        Self::open(
            source,
            ParseOptions {
                psb_key,
                mdf_key: mdf_key
                    .as_deref()
                    .map(|key| crate::mdf::MdfKey { key, key_len }),
                cancelled,
                ..ParseOptions::default()
            },
        )
    }

    /// Opens a plain PSB or MDF/MZS/PSZ source with caller-provided parameters.
    /// Parsing errors are returned directly. Resource reads keep the decoded
    /// source alive and apply middleware transformations only when requested.
    pub fn open(source: Arc<dyn ReadAt>, options: ParseOptions<'_>) -> Result<Self> {
        check_cancelled(options)?;
        let shell = if source.len() >= 4 && crate::mdf::is_mdf(&source.read_at(0, 4)?) {
            Some(crate::mdf::ShellHeader::read(&*source)?)
        } else {
            None
        };
        let source = super::open_source(source, options)?;
        let (mut document, source) = super::parse_shared_source(source, options)?;
        document.shell = shell;
        let media = media::encodings(&document, options)?;
        let mut names = BTreeMap::<(u32, bool), Vec<String>>::new();
        let mut used = BTreeSet::new();
        if let Some(root) = document.root.as_object() {
            for (name, value) in root {
                check_cancelled(options)?;
                used.insert(name.clone());
                if let PsbValue::Resource { index, is_extra } = value {
                    names
                        .entry((*index, *is_extra))
                        .or_default()
                        .push(name.clone());
                }
            }
        }
        let mut entries = Vec::new();
        let mut contents = Vec::new();
        for resource in document.resources.iter().chain(&document.extra_resources) {
            check_cancelled(options)?;
            let encoding = media.get(&(resource.index, resource.is_extra)).cloned();
            let aliases = names
                .remove(&(resource.index, resource.is_extra))
                .unwrap_or_else(|| {
                    let prefix = if resource.is_extra {
                        "extra"
                    } else {
                        "resources"
                    };
                    let extension = encoding.as_ref().map_or("bin", media::Encoding::extension);
                    let mut name = format!("{prefix}/{:04}.{extension}", resource.index);
                    while !used.insert(name.clone()) {
                        name = format!("resources/{name}");
                    }
                    vec![name]
                });
            for name in aliases {
                let kind = match encoding {
                    Some(media::Encoding::Bc7 { .. } | media::Encoding::Canvas(_)) => {
                        ResourceKind::Image
                    }
                    Some(media::Encoding::Xwma { .. }) => ResourceKind::Audio,
                    None => ResourceKind::Unknown,
                };
                entries.push(Entry {
                    name,
                    kind,
                    offset: resource.offset,
                    size: resource.size,
                    packed: None,
                });
                contents.push(Content::Resource(encoding.clone()));
            }
        }
        for (mut entry, canvas) in media::canvases(&document, options)? {
            check_cancelled(options)?;
            while !used.insert(entry.name.clone()) {
                entry.name = format!("images/{}", entry.name);
            }
            entries.push(entry);
            contents.push(Content::Resource(Some(media::Encoding::Canvas(canvas))));
        }
        let root_offset = u64::from(document.header.offset_entries);
        if let Some(root) = document.root.as_object().filter(|root| !root.is_empty()) {
            let node = document
                .nodes
                .get(&root_offset)
                .ok_or(Error::InvalidFormat)?;
            for (index, child) in node.children.iter().enumerate() {
                check_cancelled(options)?;
                let key = child
                    .name_index
                    .and_then(|index| usize::try_from(index).ok())
                    .and_then(|index| document.names.get(index))
                    .ok_or(Error::InvalidFormat)?;
                if matches!(root.get(key), Some(PsbValue::Resource { .. })) {
                    continue;
                }
                let mut name = key.clone();
                if name.is_empty() {
                    name = format!("values/{index:04}");
                    while !used.insert(name.clone()) {
                        name = format!("values/{name}");
                    }
                }
                entries.push(value_entry(&document, name, child.offset, options)?);
                contents.push(Content::Value(Some(key.clone())));
            }
        } else {
            let mut name = "root".to_owned();
            while !used.insert(name.clone()) {
                name = format!("values/{name}");
            }
            entries.push(value_entry(&document, name, root_offset, options)?);
            contents.push(Content::Value(None));
        }
        let lookup = entries
            .iter()
            .enumerate()
            .map(|(index, entry)| (entry.name.clone(), index))
            .collect();
        Ok(Self {
            document: Arc::new(document),
            source,
            entries,
            lookup,
            contents,
        })
    }

    fn index(&self, entry: &Entry) -> Result<usize> {
        self.lookup
            .get(&entry.name)
            .copied()
            .filter(|&index| {
                self.entries[index].offset == entry.offset && self.entries[index].size == entry.size
            })
            .ok_or(Error::InvalidFormat)
    }
}

impl Archive for PsbFile {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn metadata(&self) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        Some(self.document.clone())
    }

    fn entry_metadata(
        &self,
        entry: &Entry,
    ) -> Result<Option<Arc<dyn std::any::Any + Send + Sync>>> {
        let index = self.index(entry)?;
        Ok(match &self.contents[index] {
            Content::Value(key) => Some(Arc::new(super::PsbValueFile {
                document: self.document.clone(),
                key: key.clone(),
            })),
            Content::Resource(_) => None,
        })
    }

    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let index = self.index(entry)?;
        if let Content::Resource(Some(encoding @ media::Encoding::Canvas(_))) =
            &self.contents[index]
        {
            return encoding.wrap(&*self.source, &[]).map(Cow::Owned);
        }
        let raw = self.open_entry_raw(entry)?;
        match &self.contents[index] {
            Content::Resource(Some(encoding)) => encoding.wrap(&*self.source, &raw).map(Cow::Owned),
            _ => Ok(raw),
        }
    }

    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        self.index(entry)?;
        let size = usize::try_from(entry.size)
            .map_err(|_| Error::Unsupported("PSB chunk exceeds address space".into()))?;
        Ok(self.source.read_at(entry.offset, size)?)
    }

    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn ReadAt>>> {
        let index = self.index(entry)?;
        if matches!(
            self.contents[index],
            Content::Resource(None) | Content::Value(_)
        ) {
            Ok(Some(Arc::new(RangeSource::new(
                self.source.clone(),
                entry.offset,
                entry.size,
            )?)))
        } else {
            // Derived media is materialized only after that entry is requested.
            let bytes: Arc<[u8]> = self.open_entry(entry)?.into_owned().into();
            Ok(Some(Arc::new(bytes)))
        }
    }
}

// Keep original relative child offsets valid in the exported native record.
// Shared nodes contribute once; referenced string/resource tables remain in
// the retained document and are not materialized as part of this range.
fn value_entry(
    document: &Psb,
    name: String,
    offset: u64,
    options: ParseOptions<'_>,
) -> Result<Entry> {
    let mut pending = vec![offset];
    let mut visited = BTreeSet::new();
    let mut end = offset;
    while let Some(at) = pending.pop() {
        check_cancelled(options)?;
        if !visited.insert(at) {
            continue;
        }
        let node = document.nodes.get(&at).ok_or(Error::InvalidFormat)?;
        end = end.max(
            node.offset
                .checked_add(node.size)
                .ok_or_else(|| super::corrupt(at, "PSB value range overflow"))?,
        );
        pending.extend(node.children.iter().map(|child| child.offset));
    }
    Ok(Entry {
        name,
        kind: ResourceKind::Data,
        offset,
        size: end - offset,
        packed: None,
    })
}

#[cfg(test)]
#[path = "../../tests/psb/container.rs"]
mod tests;
