//! rUGP RIO object graph, indexed by the ICI manager and root child list.
//! Root lists contain only their declared objects. Further references are
//! discovered on access to an object; mounting never scans media or scripts.
//! Volume files are opened only when a requested extent needs that volume.
mod animation;
mod ici;
use nvlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, ResourceKind, Result,
};
use nvlens_io::{ArcView, BinaryReader, ReadAt};
use nvlens_script::rugp::wire::{self, Class, Object, Reader};
use std::{
    borrow::Cow,
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

const SIGNATURES: &[u32] = &[0x596e_32cd, 0x1edb_927c, 0];

#[derive(Debug, Default)]
struct Rio;
impl Format for Rio {
    fn tag(&self) -> &'static str {
        "rio/rugp"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["rio"]
    }
    fn description(&self) -> &'static str {
        "rUGP RIO object graph"
    }
}

#[derive(Debug)]
struct Sources {
    root: u32,
    primary: Arc<ArcView>,
    volumes: Vec<ici::Volume>,
    paths: Vec<PathBuf>,
    opened: Vec<OnceLock<Arc<ArcView>>>,
    shift: u32,
    children: HashMap<u32, Vec<Object>>,
    patches: HashMap<u32, (usize, u64, u32)>,
}

impl Sources {
    fn placement(&self, object: &Object) -> Result<(usize, u64, u32)> {
        if let Some(&patch) = self.patches.get(&object.offset) {
            return Ok(patch);
        }
        let address = ici::address(u64::from(object.offset), self.shift)?;
        let (index, volume) = self
            .volumes
            .iter()
            .enumerate()
            .find(|(_, v)| address >= v.base && address - v.base < v.size)
            .ok_or_else(|| Error::Corrupt {
                offset: address,
                reason: "RIO reference has no installed volume".into(),
            })?;
        let local = address - volume.base;
        if u64::from(object.size) > volume.size - local {
            return Err(Error::Corrupt {
                offset: address,
                reason: "RIO object crosses its declared volume".into(),
            });
        }
        Ok((index, local, object.size))
    }

    fn read(&self, object: &Object) -> Result<Cow<'_, [u8]>> {
        let (index, offset, size) = self.placement(object)?;
        if index == 0 {
            return Ok(Cow::Borrowed(self.primary.slice(offset, u64::from(size))?));
        }
        let slot = &self.opened[index];
        if slot.get().is_none() {
            let view = Arc::new(ArcView::open(&self.paths[index])?);
            let _ = slot.set(view);
        }
        let view = slot
            .get()
            .ok_or_else(|| Error::Unsupported("RIO volume cache entry is unavailable".into()))?;
        Ok(Cow::Borrowed(view.slice(offset, u64::from(size))?))
    }
}

#[derive(Debug)]
struct Package {
    sources: Arc<Sources>,
    entries: Vec<Entry>,
    objects: Vec<Object>,
    options: Arc<ArchiveOptions>,
    embedded: Vec<nvlens_script::rugp::Embedded>,
    references: std::cell::RefCell<HashMap<usize, bool>>,
}

fn kind(class: &str) -> ResourceKind {
    match class {
        "CRip" | "CRip007" | "CRip008" | "Cr6Ti" | "Cr6Tix" | "CRmti" | "CS5i" | "CIcon"
        | "CRsi" | "CSbm" | "CCursor" => ResourceKind::Image,
        "CWaveAudio" | "CrelicHicompAudio" | "COptimizedObs" | "COptimizedObsforR" => {
            ResourceKind::Audio
        }
        "CMpeg" | "CMovie" => ResourceKind::Video,
        "CRsa" => ResourceKind::Script,
        "CS5RFont" => ResourceKind::Font,
        _ => ResourceKind::Data,
    }
}

impl Package {
    fn new(
        sources: Arc<Sources>,
        objects: Vec<Object>,
        options: Arc<ArchiveOptions>,
    ) -> Result<Self> {
        let mut entries = Vec::with_capacity(objects.len());
        for object in &objects {
            let (_, offset, size) = sources.placement(object)?;
            let name = object
                .name
                .clone()
                .unwrap_or_else(|| format!("{:08X}.{}", object.offset, object.class.name));
            entries.push(Entry {
                name,
                kind: if object.flags & 7 == 0 {
                    kind(&object.class.name)
                } else {
                    ResourceKind::Data
                },
                offset,
                size: u64::from(size),
                packed: None,
            });
        }
        Ok(Self {
            sources,
            entries,
            objects,
            options,
            embedded: Vec::new(),
            references: std::cell::RefCell::new(HashMap::new()),
        })
    }

    fn index(&self, entry: &Entry) -> Result<usize> {
        self.entries
            .iter()
            .position(|e| e.offset == entry.offset && e.size == entry.size && e.name == entry.name)
            .ok_or_else(|| Error::Corrupt {
                offset: entry.offset,
                reason: "Entry does not belong to this RIO object index".into(),
            })
    }
}

impl ArchiveFormat for Rio {
    fn open(&self, view: &Arc<ArcView>, options: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        let path = view.path();
        let ici_path = PathBuf::from(format!("{}.ici", path.display()));
        let ici_view = ArcView::open(&ici_path)?;
        let mut index = ici::parse(ici_view.slice(0, ici_view.len())?)?;
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let first = index
            .volumes
            .first()
            .ok_or_else(|| wire::corrupt(0, "ICI has no volume"))?;
        if !path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case(&first.name))
            || first.base != 0
        {
            return Err(wire::corrupt(
                0,
                "ICI primary volume does not match the selected RIO",
            ));
        }
        let mut paths = Vec::new();
        for volume in &index.volumes {
            let relative = PathBuf::from(volume.name.replace('\\', "/"));
            if !relative
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
            {
                return Err(Error::Unsupported(
                    "RIO companion volume is not a relative filename".into(),
                ));
            }
            paths.push(parent.join(relative));
        }
        let patch_path = PathBuf::from(format!("{}.ruo", path.display()));
        let patch = match ArcView::open(&patch_path) {
            Ok(view) => Some(Arc::new(view)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let mut patches = HashMap::new();
        if let Some(patch) = &patch {
            let volume = index.volumes.len();
            patches = patch_index(patch.as_ref(), index.shift, volume)?;
            let unit = ici::address(1, index.shift)?;
            let base = ici::address(0xd000_0000u64.div_ceil(unit), index.shift)?;
            index.volumes.push(ici::Volume {
                name: patch_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                base,
                size: patch.len(),
            });
            paths.push(patch_path);
        }
        let root_id = u32::try_from(index.toc_offset >> index.shift)
            .map_err(|_| wire::corrupt(0, "RIO root exceeds address field"))?;
        let (class, objects) =
            if let (Some(patch), Some(&(_, offset, size))) = (&patch, patches.get(&root_id)) {
                read_index(patch.as_ref(), offset, u64::from(size))?
            } else {
                read_index(view.as_ref(), index.toc_offset, index.toc_size)?
            };
        let mut children: HashMap<u32, Vec<Object>> = HashMap::new();
        for object in &objects {
            let parent = object
                .parent
                .map_or(root_id, |parent| objects[parent].offset);
            children.entry(parent).or_default().push(object.clone());
        }
        let root = Object {
            class,
            flags: 0x180,
            offset: u32::try_from(index.toc_offset >> index.shift)
                .map_err(|_| wire::corrupt(0, "RIO root exceeds its address field"))?,
            size: u32::try_from(index.toc_size)
                .map_err(|_| wire::corrupt(0, "RIO root exceeds its length field"))?,
            name: None,
            parent: None,
        };
        let opened = (0..index.volumes.len())
            .map(|_| OnceLock::new())
            .collect::<Vec<_>>();
        if let Some(patch) = patch {
            let _ = opened[index.volumes.len() - 1].set(patch);
        }
        let sources = Arc::new(Sources {
            root: root_id,
            primary: view.clone(),
            volumes: index.volumes,
            paths,
            opened,
            shift: index.shift,
            children,
            patches,
        });
        Ok(Box::new(Package::new(
            sources,
            vec![root],
            Arc::new(options.clone()),
        )?))
    }
}

/// RUO's final u32 counts 12-byte (old address, new address, new size)
/// records. UnivUI::CObjectArcMan::AddUpdateFile (10016290) reads only this
/// tail; replacements retain the original logical object identity.
fn patch_index(
    source: &dyn ReadAt,
    shift: u32,
    volume: usize,
) -> Result<HashMap<u32, (usize, u64, u32)>> {
    let tail = source
        .len()
        .checked_sub(4)
        .ok_or_else(|| nvlens_io::BinaryIo::unexpected_eof("Truncated RUO tail"))?;
    let count = BinaryReader::u32_le(&source.read_at(tail, 4)?);
    let size = u64::from(count) * 12;
    let at = tail
        .checked_sub(size)
        .ok_or_else(|| nvlens_io::BinaryIo::unexpected_eof("Truncated RUO index"))?;
    let data = source.read_at(
        at,
        usize::try_from(size).map_err(|_| wire::corrupt(0, "RUO index exceeds address space"))?,
    )?;
    let mut reader = BinaryReader::new(&data);
    let mut index = HashMap::new();
    for _ in 0..count {
        let old = reader.read_u32_le()?.wrapping_sub(wire::OFFSET_BIAS);
        let offset = ici::address(
            u64::from(reader.read_u32_le()?.wrapping_sub(wire::OFFSET_BIAS)),
            shift,
        )?;
        let size = nvlens_crypto::cipher::rugp::decode_size(reader.read_u32_le()?, wire::SIZE_BIAS);
        if offset > at || u64::from(size) > at - offset {
            return Err(Error::Corrupt {
                offset,
                reason: "RUO replacement exceeds data region".into(),
            });
        }
        index.insert(old, (volume, offset, size));
    }
    Ok(index)
}

fn read_index(source: &dyn ReadAt, offset: u64, size: u64) -> Result<(Class, Vec<Object>)> {
    let data = source.read_at(
        offset,
        usize::try_from(size).map_err(|_| wire::corrupt(0, "RIO index exceeds address space"))?,
    )?;
    let mut reader = Reader::new(&data, true);
    let (signature, _, _, class) = reader.header()?;
    if signature != wire::ENCRYPTED_SIGNATURE || class.name != "CrelicUnitedGameProject" {
        return Err(Error::InvalidFormat);
    }
    let objects = reader.children()?;
    Ok((class, objects))
}

impl Archive for Package {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let index = self.index(entry)?;
        if index >= self.objects.len() {
            return Ok(Cow::Borrowed(
                &self.embedded[index - self.objects.len()].data,
            ));
        }
        let data = self.sources.read(&self.objects[index])?;
        if self.objects[index].flags & 7 == 0
            && matches!(
                self.objects[index].class.name.as_str(),
                "COptimizedObs" | "COptimizedObsforR"
            )
        {
            return Ok(Cow::Owned(nvlens_audio::rugp::to_ogg(&data)?));
        }
        if self.objects[index].offset == self.sources.root
            || (self.objects[index].flags & 7 == 0
                && matches!(
                    self.objects[index].class.name.as_str(),
                    "CIcon"
                        | "CCursor"
                        | "COptimizedObs"
                        | "COptimizedObsforR"
                        | "CWaveAudio"
                        | "CrelicHicompAudio"
                ))
        {
            return Ok(data);
        }
        Ok(Cow::Owned(wire::standalone(
            &data,
            &self.objects[index].class,
        )?))
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let index = self.index(entry)?;
        if index >= self.objects.len() {
            return Ok(Cow::Borrowed(
                &self.embedded[index - self.objects.len()].raw,
            ));
        }
        self.sources.read(&self.objects[index])
    }
    fn has_references(&self, entry: &Entry) -> bool {
        self.index(entry).is_ok_and(|i| {
            if let Some(&present) = self.references.borrow().get(&i) {
                return present;
            }
            i < self.objects.len()
                && self.objects[i].flags & 7 == 0
                && (nvlens_script::rugp::has_references(&self.objects[i].class.name)
                    || self.sources.children.contains_key(&self.objects[i].offset))
        })
    }
    fn open_references(&self, entry: &Entry) -> Result<Option<Box<dyn Archive>>> {
        if !self.has_references(entry) {
            return Ok(None);
        }
        let index = self.index(entry)?;
        if self.objects[index].class.name == "CRsi" {
            let frames =
                animation::Frames::open(self.sources.clone(), self.objects[index].clone())?;
            let present = !frames.entries().is_empty();
            self.references.borrow_mut().insert(index, present);
            return Ok(present.then(|| Box::new(frames) as Box<dyn Archive>));
        }
        let mut objects = self
            .sources
            .children
            .get(&self.objects[index].offset)
            .cloned()
            .unwrap_or_default();
        let mut embedded = Vec::new();
        if nvlens_script::rugp::has_references(&self.objects[index].class.name) {
            let (references, inline) =
                nvlens_script::rugp::contents(&self.open_entry(entry)?, &self.options)?;
            objects.extend(references);
            embedded = inline;
        }
        let mut seen = std::collections::BTreeSet::new();
        objects
            .retain(|o| o.flags & 8 != 0 && seen.insert((o.offset, o.size, o.class.name.clone())));
        if objects.is_empty() && embedded.is_empty() {
            self.references.borrow_mut().insert(index, false);
            return Ok(None);
        }
        for object in &mut objects {
            object.parent = None;
        }
        let mut package = Self::new(self.sources.clone(), objects, self.options.clone())?;
        for item in &embedded {
            package.entries.push(Entry {
                name: format!(
                    "{}@{:08X}.{}",
                    entry.name, item.span.offset, item.class.name
                ),
                kind: kind(&item.class.name),
                offset: item.span.offset,
                size: item.span.size,
                packed: None,
            });
        }
        package.embedded = embedded;
        self.references.borrow_mut().insert(index, true);
        Ok(Some(Box::new(package)))
    }
}

fn cipher_error(error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::InvalidInput {
        wire::corrupt(0, &error.to_string())
    } else {
        error.into()
    }
}

nvlens_core::register_archive!(Rio);

#[cfg(test)]
#[path = "../../tests/rugp/mod.rs"]
mod tests;
