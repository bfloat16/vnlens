//! Background archive operations shared by the desktop views.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use anyhow::{Context, Result, anyhow, bail};
use vnlens_core::{ArchiveRoute, Catalog, Entry, Opened, ResourceRoute};

// Include the virtual-path setting because it changes the child's listing.
type ReferenceArchives = HashMap<(usize, bool), Arc<MountedArchive>>;

#[derive(Debug)]
pub struct MountedArchive {
    pub path: PathBuf,
    pub source_path: PathBuf,
    pub entries: Arc<[Entry]>,
    pub paths: Vec<String>,
    /// Parsed native values belonging to virtual files; no payload reads.
    pub psb_values: std::collections::BTreeMap<usize, Arc<vnlens_middleware::psb::PsbValueFile>>,
    references: Arc<[AtomicBool]>,
    reference_archives: Arc<Mutex<ReferenceArchives>>,
    pub source: Arc<Mutex<Opened>>,
    pub directories: Vec<Directory>,
    pub game: Arc<vnlens_engine::Identification>,
    /// Filesystem wrappers are folders, not proprietary game archives.
    pub filesystem: bool,
    // Keep temporary nested sources alive until all mapped readers are dropped.
    _backing: Option<Arc<TemporaryArchive>>,
}

impl MountedArchive {
    pub fn has_references(&self, index: usize) -> bool {
        self.references[index].load(Ordering::Relaxed)
    }
    /// Opens the index and, only when requested, virtual-path metadata.
    /// The UI never locks the source on its event thread.
    pub fn open(
        path: PathBuf,
        virtual_paths: bool,
        game: Arc<vnlens_engine::Identification>,
    ) -> Result<Option<Self>> {
        let ResourceRoute::Archive(route) = game.route_path(&path)? else {
            return Ok(None);
        };
        Self::open_routed(path, &route, virtual_paths, game).map(Some)
    }

    fn open_routed(
        path: PathBuf,
        route: &ArchiveRoute,
        virtual_paths: bool,
        game: Arc<vnlens_engine::Identification>,
    ) -> Result<Self> {
        let catalog = Catalog::load();
        let opened =
            catalog.open_source(game.files.source(&path)?, &path.to_string_lossy(), route)?;
        let opened = opened
            .map(Ok)
            .unwrap_or_else(|| catalog.open_view(Arc::new(game.files.open(&path)?), route))
            .with_context(|| format!("Opening {} with {:?}", path.display(), game.engine))?;
        let source_path = game.files.canonicalize(&path)?;
        Self::from_opened(path, source_path, opened, virtual_paths, game)
    }

    /// NS partition and RomFS indices are ordinary game directories. Register
    /// their streaming file sources without reading payloads or creating disk
    /// copies, then run the directory identification rules over those names.
    pub fn filesystem_target(&self, cancel: &AtomicBool) -> Result<Option<crate::browser::Target>> {
        let opened = self
            .source
            .lock()
            .map_err(|_| anyhow!("Archive reader is unavailable"))?;
        if !matches!(opened.format_tag, "ns/pfs0" | "ns/romfs") {
            return Ok(None);
        }
        // An NSP/PFS containing other NS filesystems is a transport directory.
        // Its children retain their original index origins (e.g. XCI's secure
        // partition), and each entered filesystem establishes its own context.
        // The game directory is identified once actual files become visible.
        let nested_filesystem = |entry: &Entry| {
            matches!(self.game.resource_route(&entry.name, vnlens_core::ResourceOrigin::Entry(entry.kind), &[]),
                    ResourceRoute::Archive(route) if route.tag.starts_with("ns/"))
        };
        if opened.format_tag == "ns/pfs0"
            && opened.archive.entries().iter().any(nested_filesystem)
            && opened.archive.entries().iter().all(|entry| {
                nested_filesystem(entry)
                    || Path::new(&entry.name).extension().is_some_and(|ext| {
                        ext.eq_ignore_ascii_case("tik")
                            || ext.eq_ignore_ascii_case("cert")
                            || entry.name.to_ascii_lowercase().ends_with(".cnmt.xml")
                    })
            })
        {
            return Ok(None);
        }
        let root = self.source_path.clone();
        let mut files = vnlens_io::FileSystem::isolated(root.clone());
        for entry in opened.archive.entries() {
            if cancel.load(Ordering::Relaxed) {
                return Err(vnlens_core::Error::Cancelled.into());
            }
            let source = opened
                .archive
                .open_entry_source_cancellable(entry, cancel)?
                .ok_or_else(|| anyhow!("NS filesystem entry has no streaming source"))?;
            files.insert(root.join(entry.name.replace('\\', "/")), source)?;
        }
        drop(opened);
        let game = self
            .game
            .for_filesystem(root.clone(), Arc::new(files), cancel)?;
        Ok(Some(crate::browser::Target::Directory(
            root,
            Arc::new(game),
        )))
    }

    fn from_opened(
        path: PathBuf,
        source_path: PathBuf,
        opened: Opened,
        virtual_paths: bool,
        game: Arc<vnlens_engine::Identification>,
    ) -> Result<Self> {
        let mut paths: Vec<_> = opened
            .archive
            .entries()
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        if virtual_paths {
            for (index, path) in opened.archive.virtual_paths()? {
                *paths
                    .get_mut(index)
                    .ok_or_else(|| anyhow!("Virtual path refers to a missing archive entry"))? =
                    path;
            }
        }
        Ok(Self {
            filesystem: opened.format_tag.starts_with("ns/"),
            source_path,
            path,
            directories: directories(&paths),
            entries: opened.archive.entries().into(),
            psb_values: psb_values(&*opened.archive)?,
            references: opened
                .archive
                .entries()
                .iter()
                .map(|entry| AtomicBool::new(opened.archive.has_references(entry)))
                .collect(),
            reference_archives: Arc::default(),
            paths,
            source: Arc::new(Mutex::new(opened)),
            game,
            _backing: None,
        })
    }

    /// Opens the engine-selected logical container without preloading its
    /// resources. The caller preserves its original name and index routing.
    /// Formats requiring mmap retain their mapped temporary path.
    pub fn open_nested_source(
        name: &str,
        source: Arc<dyn vnlens_io::ReadAt>,
        route: &ArchiveRoute,
        virtual_paths: bool,
        game: Arc<vnlens_engine::Identification>,
    ) -> Result<Self> {
        if let Some(opened) = Catalog::load().open_source(source.clone(), name, route)? {
            return Self::from_opened(
                PathBuf::from(name),
                PathBuf::from(name),
                opened,
                virtual_paths,
                game,
            );
        }
        let bytes = source.read_at(0, usize::try_from(source.len())?)?;
        Self::open_nested(name, &bytes, route, virtual_paths, game)
    }

    /// Materializes only the selected nested container, preserving its extension.
    pub fn open_nested(
        name: &str,
        bytes: &[u8],
        route: &ArchiveRoute,
        virtual_paths: bool,
        game: Arc<vnlens_engine::Identification>,
    ) -> Result<Self> {
        let backing = TemporaryArchive::new()?;
        let file_name = name.rsplit(['/', '\\']).next().unwrap_or("archive");
        let path = vnlens_io::filesystem::write_under(&backing.0, file_name, bytes)?;
        // Keep the selected route and its options: the temporary filename does
        // not contain the original parent path used to select engine keys.
        let mut opened = Self::open_routed(path, route, virtual_paths, game)?;
        opened.path = PathBuf::from(name);
        opened._backing = Some(Arc::new(backing));
        Ok(opened)
    }

    pub fn descendants(&self, directory: usize) -> Vec<usize> {
        let mut pending = vec![Node::Directory(directory)];
        let mut indices = Vec::new();
        while let Some(node) = pending.pop() {
            match node {
                Node::Entry(index) => indices.push(index),
                Node::Directory(index) => pending.extend(
                    self.directories[index]
                        .items
                        .iter()
                        .rev()
                        .map(|item| item.node),
                ),
            }
        }
        indices
    }

    /// Opens one selected reference graph without materializing its backing
    /// archive or asking a filename-based reader to rediscover its context.
    /// Successful children and empty results are retained for navigation reuse.
    pub fn open_references(&self, index: usize, virtual_paths: bool) -> Result<Option<Arc<Self>>> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| anyhow!("Missing referenced object"))?;
        let mut cached = self
            .reference_archives
            .lock()
            .map_err(|_| anyhow!("Reference cache is unavailable"))?;
        if let Some(archive) = cached.get(&(index, virtual_paths)) {
            return Ok(Some(archive.clone()));
        }
        if !self.has_references(index) {
            return Ok(None);
        }
        let source = self
            .source
            .lock()
            .map_err(|_| anyhow!("Archive reader is unavailable"))?;
        let Some(archive) = source.archive.open_references(entry)? else {
            self.references[index].store(false, Ordering::Relaxed);
            return Ok(None);
        };
        if archive.entries().is_empty() {
            self.references[index].store(false, Ordering::Relaxed);
            return Ok(None);
        }
        let mut paths = archive
            .entries()
            .iter()
            .map(|e| e.name.clone())
            .collect::<Vec<_>>();
        if virtual_paths {
            for (index, path) in archive.virtual_paths()? {
                *paths
                    .get_mut(index)
                    .ok_or_else(|| anyhow!("Referenced virtual path has no entry"))? = path;
            }
        }
        let mounted = Arc::new(Self {
            filesystem: self.filesystem,
            path: PathBuf::from(&entry.name),
            source_path: self.source_path.clone(),
            entries: archive.entries().into(),
            psb_values: psb_values(&*archive)?,
            references: archive
                .entries()
                .iter()
                .map(|e| AtomicBool::new(archive.has_references(e)))
                .collect(),
            reference_archives: Arc::default(),
            directories: directories(&paths),
            paths,
            source: Arc::new(Mutex::new(Opened {
                format_tag: source.format_tag,
                archive,
            })),
            game: self.game.clone(),
            _backing: self._backing.clone(),
        });
        cached.insert((index, virtual_paths), mounted.clone());
        Ok(Some(mounted))
    }

    /// Builds an immutable presentation snapshot off the UI thread. Storage
    /// entries and their reader remain shared, including nested-file lifetime.
    pub fn with_paths(&self, paths: Vec<String>) -> Result<Self> {
        if paths.len() != self.entries.len() {
            bail!("Recovered path count differs from archive index");
        }
        Ok(Self {
            filesystem: self.filesystem,
            path: self.path.clone(),
            source_path: self.source_path.clone(),
            entries: self.entries.clone(),
            psb_values: self.psb_values.clone(),
            directories: directories(&paths),
            paths,
            references: self.references.clone(),
            reference_archives: self.reference_archives.clone(),
            source: self.source.clone(),
            game: self.game.clone(),
            _backing: self._backing.clone(),
        })
    }

    /// A renamed hash directory can expand into several real path components.
    /// Keep navigation at the common parent of the same original descendants.
    pub fn renamed_directory(&self, directory: usize, newer: &Self) -> usize {
        if directory == 0 {
            return 0;
        }
        let mut common: Option<Vec<&str>> = None;
        for index in self.descendants(directory) {
            let parent = newer.paths[index]
                .rsplit_once('/')
                .map_or("", |(dir, _)| dir);
            let parts: Vec<_> = parent.split('/').filter(|s| !s.is_empty()).collect();
            if let Some(common) = &mut common {
                let count = common
                    .iter()
                    .zip(&parts)
                    .take_while(|(a, b)| a == b)
                    .count();
                common.truncate(count);
            } else {
                common = Some(parts);
            }
        }
        let mut id = 0;
        for part in common.unwrap_or_default() {
            let Some(next) = newer.directories[id].items.iter().find_map(|item| {
                if item.name == part
                    && let Node::Directory(next) = item.node
                {
                    Some(next)
                } else {
                    None
                }
            }) else {
                break;
            };
            id = next;
        }
        id
    }
}

fn psb_values(
    archive: &dyn vnlens_core::Archive,
) -> Result<std::collections::BTreeMap<usize, Arc<vnlens_middleware::psb::PsbValueFile>>> {
    let mut values = std::collections::BTreeMap::new();
    for (index, entry) in archive.entries().iter().enumerate() {
        if let Some(metadata) = archive.entry_metadata(entry)?
            && let Ok(value) = metadata.downcast::<vnlens_middleware::psb::PsbValueFile>()
        {
            values.insert(index, value);
        }
    }
    Ok(values)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node {
    Directory(usize),
    Entry(usize),
}

#[derive(Debug)]
pub struct Item {
    pub name: String,
    pub node: Node,
}

#[derive(Debug, Default)]
pub struct Directory {
    pub items: Vec<Item>,
    pub parent: Option<usize>,
}

fn directories(paths: &[String]) -> Vec<Directory> {
    let mut directories = vec![Directory::default()];
    let mut folders = HashMap::new();
    for (index, path) in paths.iter().enumerate() {
        let mut parts = path.split(['/', '\\']).peekable();
        let mut parent = 0;
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                directories[parent].items.push(Item {
                    name: part.to_owned(),
                    node: Node::Entry(index),
                });
            } else {
                let key = (parent, part.to_owned());
                parent = *folders.entry(key).or_insert_with(|| {
                    let id = directories.len();
                    directories.push(Directory {
                        items: Vec::new(),
                        parent: Some(parent),
                    });
                    directories[parent].items.push(Item {
                        name: part.to_owned(),
                        node: Node::Directory(id),
                    });
                    id
                });
            }
        }
    }
    for directory in &mut directories {
        directory.items.sort_by(|a, b| {
            matches!(a.node, Node::Entry(_))
                .cmp(&matches!(b.node, Node::Entry(_)))
                .then_with(|| a.name.cmp(&b.name))
        });
    }
    directories
}

#[derive(Debug)]
struct TemporaryArchive(PathBuf);

impl TemporaryArchive {
    fn new() -> Result<Self> {
        use std::sync::atomic::AtomicU64;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        loop {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "vnlens-nested-{}-{time}-{sequence}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl Drop for TemporaryArchive {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            tracing::warn!(%error, "Cannot remove nested archive cache");
        }
    }
}

/// Reads exactly the selected entry; a superseded request never opens content.
pub fn read_entry(
    source: &Mutex<Opened>,
    index: usize,
    raw: bool,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    let opened = source
        .lock()
        .map_err(|_| anyhow!("Archive reader is unavailable"))?;
    if cancelled.load(Ordering::Relaxed) {
        return Err(vnlens_core::Error::Cancelled.into());
    }
    let entry = opened
        .archive
        .entries()
        .get(index)
        .ok_or_else(|| anyhow!("Selected entry no longer exists"))?;
    let data = if raw {
        opened.archive.open_entry_raw(entry)
    } else {
        opened.archive.open_entry(entry)
    };
    data.map(|bytes| bytes.into_owned()).with_context(|| {
        format!(
            "Reading {} [{} at 0x{:x}]",
            entry.name, opened.format_tag, entry.offset
        )
    })
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Progress {
    pub completed: usize,
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
}

#[derive(Debug)]
pub struct Extraction {
    pub progress: Progress,
    pub cancelled: bool,
}

/// Extracts requested entries and their explicit reference containers. A visited
/// set preserves shared objects and cycles; parsing stays in domain readers.
pub fn extract(
    archive: &MountedArchive,
    indices: &[usize],
    output: &Path,
    raw: bool,
    cancelled: &AtomicBool,
    mut report: impl FnMut(Progress, Option<String>),
) -> Result<Extraction> {
    let opened = archive
        .source
        .lock()
        .map_err(|_| anyhow!("Archive reader is unavailable"))?;
    let mut progress = Progress {
        total: indices.len(),
        ..Progress::default()
    };
    let mut pending = Vec::<Box<dyn vnlens_core::Archive>>::new();
    let mut owned: Option<Box<dyn vnlens_core::Archive>> = None;
    let mut seen = std::collections::HashSet::new();
    loop {
        let source = owned.as_deref().unwrap_or(opened.archive.as_ref());
        let selected = if owned.is_none() {
            indices.to_vec()
        } else {
            (0..source.entries().len()).collect()
        };
        for index in selected {
            if cancelled.load(Ordering::Relaxed) {
                return Ok(Extraction {
                    progress,
                    cancelled: true,
                });
            }
            let Some(entry) = source.entries().get(index) else {
                bail!("Selected entry no longer exists");
            };
            if !seen.insert((entry.name.clone(), entry.offset, entry.size)) {
                progress.completed += 1;
                report(progress, None);
                continue;
            }
            let path = if owned.is_none() {
                archive.paths[index].as_str()
            } else {
                entry.name.as_str()
            };
            let result = (|| -> Result<()> {
                let bytes = if raw {
                    source.open_entry_raw(entry)?
                } else {
                    source.open_entry(entry)?
                };
                if cancelled.load(Ordering::Relaxed) {
                    return Err(vnlens_core::Error::Cancelled.into());
                }
                vnlens_io::filesystem::write_under(output, path, &bytes)?;
                if source.has_references(entry)
                    && let Some(references) = source.open_references(entry)?
                {
                    progress.total += references.entries().len();
                    pending.push(references);
                }
                Ok(())
            })();
            let error = match result {
                Ok(()) => {
                    progress.succeeded += 1;
                    None
                }
                Err(error)
                    if matches!(error.downcast_ref(), Some(vnlens_core::Error::Cancelled)) =>
                {
                    return Ok(Extraction {
                        progress,
                        cancelled: true,
                    });
                }
                Err(error) => {
                    progress.failed += 1;
                    Some(format!(
                        "{} [{} at 0x{:x}]: {error:#}",
                        entry.name, opened.format_tag, entry.offset
                    ))
                }
            };
            progress.completed += 1;
            report(progress, error);
        }
        owned = pending.pop();
        if owned.is_none() {
            break;
        }
    }
    Ok(Extraction {
        progress,
        cancelled: false,
    })
}

#[cfg(test)]
#[path = "../tests/archive.rs"]
mod tests;
