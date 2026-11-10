//! C,system split archives, verified against sub_41EBB0, sub_41A390 and
//! sub_410E00. Arc01/02/03/07 are decimal-framed LZSS indexes for Arc04/05/06/08.
//! Resources/Data00 stores per-volume LE (unpacked, stored, u64 offset) tables
//! followed by animation metadata. Only the requested volume is mapped.
mod index;
mod movie;
use std::{
    borrow::Cow,
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};
use vnlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, ResourceKind, Result,
};
use vnlens_io::{ArcView, RangeSource, ReadAt};
const SIGNATURES: &[u32] = &[0];
#[derive(Debug, Default)]
struct Dat;
impl Format for Dat {
    fn tag(&self) -> &'static str {
        "dat/csystem"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["dat"]
    }
    fn description(&self) -> &'static str {
        "C,system split resource archives"
    }
}
impl ArchiveFormat for Dat {
    fn open(&self, view: &Arc<ArcView>, options: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        let name = view
            .path()
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let root =
            options.paths.get("csystem_root").cloned().ok_or_else(|| {
                Error::UnknownScheme(Some("C,system game root is missing".into()))
            })?;
        let mut parts = BTreeMap::new();
        let mut payloads = BTreeMap::new();
        let (source, entries, volumes) = if name == "data00.dat" {
            let tables = index::resources(view.slice(0, view.len())?)?;
            let entries = tables
                .iter()
                .enumerate()
                .map(|(i, t)| Entry {
                    name: format!("Data{i:03}.dat.index"),
                    kind: ResourceKind::Archive,
                    offset: t.start,
                    size: t.size,
                    packed: None,
                })
                .collect();
            (view.clone(), entries, true)
        } else if let Some(id) = name
            .strip_prefix("data")
            .and_then(|s| s.strip_suffix(".dat"))
            .and_then(|s| s.parse::<usize>().ok())
        {
            let idx = view.open_related(root.join("Resources/Data00.dat"))?;
            let tables = index::resources(idx.slice(0, idx.len())?)?;
            let table = tables
                .into_iter()
                .nth(id)
                .ok_or_else(|| bad(0, "C,system volume is absent from Data00"))?;
            (view.clone(), table.entries, false)
        } else if name == "arc00.dat" {
            (view.clone(), index::configuration(view.as_ref())?, false)
        } else {
            let stem = name
                .strip_prefix("arc")
                .and_then(|s| s.strip_suffix(".dat"))
                .ok_or(Error::InvalidFormat)?;
            let (idx, payload) = match stem {
                "01" | "04" => (1, 4),
                "02" | "05" | "05a" | "05b" => (2, 5),
                "03" | "06" => (3, 6),
                "07" | "08" | "08a" => (7, 8),
                "09" | "10" => (9, 10),
                _ => return Err(Error::Unsupported(format!("C,system archive {name}"))),
            };
            let idx = view.open_related(root.join(format!("Arc{idx:02}.dat")))?;
            let mut entries = Vec::new();
            for (entry, part) in index::arc(&idx)? {
                let suffix = match (payload, part) {
                    (_, 0) => "",
                    (5 | 8, 1) => "a",
                    (5, 2) => "b",
                    _ => return Err(bad(entry.offset, "Unsupported C,system payload selector")),
                };
                let path = root.join(format!("Arc{payload:02}{suffix}.dat"));
                payloads.entry(part).or_insert_with(|| Payload {
                    path,
                    view: OnceLock::new(),
                });
                if parts.insert(entry.name.clone(), part).is_some() {
                    return Err(bad(entry.offset, "Duplicate C,system resource ID and type"));
                }
                entries.push(entry);
            }
            (Arc::new(idx), entries, false)
        };
        for entry in &entries {
            if payloads.is_empty() && !entry.check_placement(source.len()) {
                return Err(bad(entry.offset, "C,system entry exceeds its data file"));
            }
        }
        Ok(Box::new(Package {
            view: source,
            entries,
            root,
            options: options.clone(),
            volumes,
            parts,
            payloads,
        }))
    }
}
#[derive(Debug)]
struct Payload {
    path: PathBuf,
    view: OnceLock<Arc<ArcView>>,
}

#[derive(Debug)]
struct Package {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
    root: PathBuf,
    options: ArchiveOptions,
    volumes: bool,
    parts: BTreeMap<String, u8>,
    payloads: BTreeMap<u8, Payload>,
}
impl Package {
    fn source(&self, entry: &Entry) -> Result<&Arc<ArcView>> {
        let Some(part) = self.parts.get(&entry.name) else {
            return Ok(&self.view);
        };
        let payload = self.payloads.get(part).ok_or(Error::InvalidFormat)?;
        if payload.view.get().is_none() {
            let view = Arc::new(self.view.open_related(&payload.path)?);
            let _ = payload.view.set(view);
        }
        payload.view.get().ok_or(Error::InvalidFormat)
    }
}
impl Archive for Package {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let data = self.source(entry)?.slice(entry.offset, entry.size)?;
        let bytes = if let Some(packed) = entry.packed.filter(|p| p.is_packed) {
            Cow::Owned(index::inflate(
                data,
                usize::try_from(packed.unpacked_size)
                    .map_err(|_| bad(entry.offset, "C,system output exceeds address space"))?,
            )?)
        } else {
            Cow::Borrowed(data)
        };
        if entry.kind == ResourceKind::Audio {
            let key = self.options.keys.get("csystem_audio").ok_or_else(|| {
                Error::UnknownScheme(Some("C,system audio key is missing".into()))
            })?;
            let decoded = vnlens_audio::csystem::decode_envelope(&bytes, key.bytes())?;
            if let Cow::Owned(out) = decoded {
                return Ok(Cow::Owned(out));
            }
            if decoded.len() != bytes.len() {
                return Ok(Cow::Owned(decoded.into_owned()));
            }
        }
        if entry.name.ends_with(".y0") {
            let mut r = vnlens_io::BinaryReader::new(&bytes);
            r.read_u32_le()?;
            let mut out = r.read_bytes(r.remaining())?.to_vec();
            vnlens_crypto::cipher::csystem::movie(&mut out, 0);
            return Ok(Cow::Owned(out));
        }
        Ok(bytes)
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(
            self.source(entry)?.slice(entry.offset, entry.size)?,
        ))
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn ReadAt>>> {
        if entry.packed.is_some_and(|p| p.is_packed) || entry.kind == ResourceKind::Audio {
            return Ok(None);
        }
        if entry.name.ends_with(".y0") {
            return movie::Movie::open(self.source(entry)?.clone(), entry).map(Some);
        }
        Ok(Some(Arc::new(RangeSource::new(
            self.source(entry)?.clone(),
            entry.offset,
            entry.size,
        )?)))
    }
    fn has_references(&self, _: &Entry) -> bool {
        self.volumes
    }
    fn open_references(&self, entry: &Entry) -> Result<Option<Box<dyn Archive>>> {
        if !self.volumes {
            return Ok(None);
        }
        let name = entry
            .name
            .strip_suffix(".index")
            .ok_or(Error::InvalidFormat)?;
        let path = self.root.join("Resources").join(name);
        let view = Arc::new(self.view.open_related(path)?);
        Dat.open(&view, &self.options).map(Some)
    }
    fn read_companion(&self, name: &str) -> Result<Option<Vec<u8>>> {
        if let Some(ordinal) = name
            .strip_prefix("picture/")
            .and_then(|name| name.strip_suffix(".b0"))
            .and_then(|name| name.parse::<usize>().ok())
        {
            return self
                .entries
                .iter()
                .filter(|entry| entry.name.ends_with(".b0"))
                .nth(ordinal)
                .map(|entry| self.open_entry(entry).map(Cow::into_owned))
                .transpose();
        }
        // Modern image resources carry an absolute resource ID. The high
        // decimal group selects DataNNN and the low group its index ordinal.
        let Some(id) = Path::new(name)
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<u32>().ok())
        else {
            return Ok(None);
        };
        let Some(volume) = (id / 10_000_000).checked_sub(1) else {
            return Ok(None);
        };
        let view = Arc::new(
            self.view
                .open_related(self.root.join(format!("Resources/Data{volume:03}.dat")))?,
        );
        let package = Dat.open(&view, &self.options)?;
        package
            .entries()
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| package.open_entry(entry).map(Cow::into_owned))
            .transpose()
    }
}
fn bad(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}
vnlens_core::register_archive!(Dat);

#[cfg(test)]
#[path = "../../tests/csystem/mod.rs"]
mod tests;
