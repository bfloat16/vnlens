//! Folder navigation shared by disk directories and mounted archive directories.
//! Listing uses filesystem metadata or archive indices. rUGP navigation also
//! resolves the displayed objects' immediate references before publishing rows.

use crate::archive::{self, Extraction, MountedArchive, Node, Progress};
use anyhow::{Context, Result, anyhow};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use vnlens_core::{ResourceKind, ResourceOrigin, ResourceRoute};
use vnlens_engine::{ArchiveSet, Identification};
#[derive(Clone, Debug)]
pub enum Target {
    /// Virtual root populated only with paths explicitly opened by the user.
    Opened,
    Directory(PathBuf, Arc<Identification>),
    File(PathBuf, Arc<Identification>),
    /// One reader entry point with its installed companion files.
    ArchiveSet(Arc<ArchiveSet>, Arc<Identification>),
    ArchiveDirectory {
        archive: Arc<MountedArchive>,
        directory: usize,
    },
    Entry {
        archive: Arc<MountedArchive>,
        index: usize,
    },
}

impl Target {
    pub fn set_compose_pimg(&self, enabled: bool) {
        match self {
            Self::Directory(_, game) | Self::File(_, game) | Self::ArchiveSet(_, game) => {
                game.set_compose_pimg(enabled);
            }
            Self::ArchiveDirectory { archive, .. } | Self::Entry { archive, .. } => {
                archive.game.set_compose_pimg(enabled);
            }
            Self::Opened => {}
        }
    }
    pub fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Opened, Self::Opened) => true,
            (Self::Directory(a, _), Self::Directory(b, _))
            | (Self::File(a, _), Self::File(b, _)) => a == b,
            (Self::ArchiveSet(a, _), Self::ArchiveSet(b, _)) => a.primary == b.primary,
            (
                Self::ArchiveDirectory {
                    archive: a,
                    directory: ai,
                },
                Self::ArchiveDirectory {
                    archive: b,
                    directory: bi,
                },
            ) => Arc::ptr_eq(a, b) && ai == bi,
            (
                Self::Entry {
                    archive: a,
                    index: ai,
                },
                Self::Entry {
                    archive: b,
                    index: bi,
                },
            ) => Arc::ptr_eq(a, b) && ai == bi,
            _ => false,
        }
    }
    pub fn is_directory(&self) -> bool {
        matches!(
            self,
            Self::Opened | Self::Directory(..) | Self::ArchiveDirectory { .. }
        )
    }
    pub fn name(&self) -> String {
        match self {
            Self::Opened => "Opened".into(),
            Self::ArchiveSet(set, _) => set
                .primary
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            Self::Directory(path, _) | Self::File(path, _) => path
                .file_name()
                .unwrap_or_else(|| path.as_os_str())
                .to_string_lossy()
                .into_owned(),
            Self::Entry { archive, index } => archive.paths[*index]
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("")
                .to_owned(),
            Self::ArchiveDirectory { archive, .. } => archive
                .path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
        }
    }
    pub fn archive_hint(&self) -> bool {
        match self {
            Self::ArchiveSet(..) => true,
            Self::File(..) => matches!(self.resource_route(&[]), Ok(ResourceRoute::Archive(_))),
            Self::Entry { archive, index } => {
                archive.has_references(*index)
                    || matches!(self.resource_route(&[]), Ok(ResourceRoute::Archive(_)))
            }
            _ => false,
        }
    }
    /// Preserves native storage names for headerless formats; recovered names
    /// supply a route only when the stored name has no known format.
    /// Classification never reads payloads; callers supply a prefix on access.
    pub fn resource_route(&self, header: &[u8]) -> Result<ResourceRoute> {
        match self {
            Self::File(path, game) => {
                Ok(game.resource_route(&path.to_string_lossy(), ResourceOrigin::File, header))
            }
            Self::Entry { archive, index } => {
                if archive.psb_values.contains_key(index) {
                    return Ok(ResourceRoute::Other(ResourceKind::Data));
                }
                let entry = &archive.entries[*index];
                let origin = ResourceOrigin::Entry(entry.kind);
                // Choose the original or recovered name from index metadata
                // first. A PSB header must not erase a selected PIMG image route.
                let named = archive.game.resource_route(&entry.name, origin, &[]);
                if matches!(named, ResourceRoute::Other(_)) && archive.paths[*index] != entry.name {
                    Ok(archive
                        .game
                        .resource_route(&archive.paths[*index], origin, header))
                } else {
                    Ok(archive.game.resource_route(&entry.name, origin, header))
                }
            }
            _ => Err(anyhow!(
                "Resource routing requires an identified file or entry"
            )),
        }
    }
    fn video_source(&self, raw: bool) -> Result<Option<Arc<dyn vnlens_io::ReadAt>>> {
        let Self::File(path, game) = self else {
            return Ok(None);
        };
        let ResourceRoute::Video(tag) = game.route_path(path)? else {
            return Ok(None);
        };
        let source = game.files.source(path)?;
        if raw {
            return Ok(Some(source));
        }
        vnlens_video::decode_source_as(tag, source, &self.name(), game.resource_options())
            .map(Some)
            .map_err(Into::into)
    }
    pub fn read(&self, raw: bool, cancel: &AtomicBool) -> Result<Vec<u8>> {
        if cancel.load(Ordering::Relaxed) {
            return Err(vnlens_core::Error::Cancelled.into());
        }
        match self {
            Self::File(path, game) => {
                if !raw && let Some(source) = self.video_source(false)? {
                    let mut output = Vec::new();
                    let mut offset = 0;
                    while offset < source.len() {
                        if cancel.load(Ordering::Relaxed) {
                            return Err(vnlens_core::Error::Cancelled.into());
                        }
                        let size = (source.len() - offset).min(65536) as usize;
                        output.extend_from_slice(&source.read_at(offset, size)?);
                        offset += size as u64;
                    }
                    return Ok(output);
                }
                let bytes = game
                    .files
                    .read(path)
                    .with_context(|| format!("Reading {}", path.display()))?;
                if !raw
                    && let ResourceRoute::Script(tag) = self.resource_route(&bytes)?
                    && let std::borrow::Cow::Owned(decoded) =
                        vnlens_script::decode_with_resources_as(
                            tag,
                            &bytes,
                            Some(&crate::resource::FileResources(path, &game.files)),
                            game.resource_options(),
                            cancel,
                        )?
                {
                    return Ok(decoded);
                }
                Ok(bytes)
            }
            Self::Entry { archive, index } => {
                archive::read_entry(&archive.source, *index, raw, cancel)
            }
            _ => Err(anyhow!("Select a file to read its contents")),
        }
    }
    pub fn export_name(&self) -> String {
        match self {
            Self::Entry { archive, index } => archive.paths[*index].clone(),
            _ => self.name(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Item {
    pub name: String,
    pub target: Target,
    pub kind: ResourceKind,
    pub size: Option<u64>,
    pub count: Option<usize>,
    pub container: bool,
}
impl Item {
    /// Reference owners may expose both navigation and a resource preview.
    /// Containers selected by the engine route only expose their filesystem.
    pub fn can_preview(&self) -> bool {
        if !self.container {
            return true;
        }
        let Target::Entry { archive, index } = &self.target else {
            return false;
        };
        archive.has_references(*index)
            && matches!(self.target.resource_route(&[]), Ok(route) if !matches!(route, ResourceRoute::Archive(_)))
    }

    pub fn set_compose_pimg(&mut self, enabled: bool) {
        self.target.set_compose_pimg(enabled);
        if !self
            .target
            .name()
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("pimg"))
        {
            return;
        }
        let refreshed = Self::from_target(self.target.clone(), self.size);
        self.kind = refreshed.kind;
        self.container = refreshed.container;
        self.count = refreshed.count;
    }
    #[cfg(test)]
    pub fn from_path(path: PathBuf) -> Result<Self> {
        Self::from_path_cancellable(path, &AtomicBool::new(false), &|_, _| {})
    }
    pub fn from_path_cancellable(
        path: PathBuf,
        cancel: &AtomicBool,
        progress: &(dyn Fn(u64, u64) + Sync),
    ) -> Result<Self> {
        let metadata =
            std::fs::metadata(&path).with_context(|| format!("Opening {}", path.display()))?;
        let game = Arc::new(
            vnlens_engine::identify_with_progress(&path, cancel, progress)?.ok_or_else(|| {
                anyhow!("Game engine was not identified; resource processing is disabled")
            })?,
        );
        let target = if metadata.is_dir() {
            Target::Directory(path, game)
        } else {
            if let Some(parent) = path.parent() {
                let files = game
                    .files
                    .read_dir(parent)?
                    .into_iter()
                    .filter_map(|entry| (!entry.metadata.directory).then_some(entry.path))
                    .collect::<Vec<_>>();
                if let Some(set) = game
                    .archive_sets(&files)
                    .into_iter()
                    .find(|set| set.members.contains(&path))
                {
                    return Ok(Self::from_set(set, game));
                }
            }
            Target::File(path, game)
        };
        Ok(Self::from_target(target, Some(metadata.len())))
    }
    fn from_target(target: Target, size: Option<u64>) -> Self {
        let name = target.name();
        let container = target.is_directory() || target.archive_hint();
        let (kind, count) = match &target {
            Target::ArchiveSet(set, _) => (ResourceKind::Archive, Some(set.members.len())),
            Target::File(..) => (
                target
                    .resource_route(&[])
                    .map_or(ResourceKind::Unknown, |route| route.kind()),
                None,
            ),
            Target::ArchiveDirectory { archive, directory } => (
                ResourceKind::Archive,
                Some(archive.directories[*directory].items.len()),
            ),
            Target::Entry { .. } => (
                target
                    .resource_route(&[])
                    .map_or(ResourceKind::Unknown, |route| route.kind()),
                None,
            ),
            _ => (ResourceKind::Unknown, None),
        };
        Self {
            name,
            kind,
            count,
            container,
            size: if target.is_directory() { None } else { size },
            target,
        }
    }

    fn from_set(set: ArchiveSet, game: Arc<Identification>) -> Self {
        let size = set.members.iter().try_fold(0u64, |sum, path| {
            sum.checked_add(game.files.metadata(path).ok()?.len)
        });
        Self::from_target(Target::ArchiveSet(Arc::new(set), game), size)
    }
}

#[derive(Debug)]
pub struct Folder {
    pub target: Target,
    pub items: Vec<Item>,
}
impl Folder {
    pub fn empty(target: Target) -> Self {
        Self {
            target,
            items: Vec::new(),
        }
    }
    pub fn archive(archive: Arc<MountedArchive>, directory: usize) -> Self {
        let items: Vec<Item> = archive.directories[directory]
            .items
            .iter()
            .map(|item| {
                let (target, size) = match item.node {
                    Node::Directory(directory) => (
                        Target::ArchiveDirectory {
                            archive: archive.clone(),
                            directory,
                        },
                        None,
                    ),
                    Node::Entry(index) => (
                        Target::Entry {
                            archive: archive.clone(),
                            index,
                        },
                        Some(archive.entries[index].size),
                    ),
                };
                let mut row = Item::from_target(target, size);
                row.name = item.name.clone();
                row
            })
            .collect();
        let mut folder = Self {
            target: Target::ArchiveDirectory { archive, directory },
            items,
        };
        folder.sort();
        folder
    }
    pub fn insert(&mut self, item: Item) -> usize {
        if let Some(row) = self
            .items
            .iter()
            .position(|old| old.target.same(&item.target))
        {
            return row;
        }
        let target = item.target.clone();
        self.items.push(item);
        self.sort();
        self.items
            .iter()
            .position(|entry| entry.target.same(&target))
            .unwrap_or(0)
    }
    fn sort(&mut self) {
        self.items.sort_by(|a, b| {
            b.container
                .cmp(&a.container)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
    }

    /// Resolve one layer on the navigation worker so an empty reference owner
    /// is already a leaf when clicked. Opening a cached child prepares its own
    /// rows later; this never recursively scans the object graph or decodes media.
    fn prepare_references(&mut self, cancel: &AtomicBool, virtual_paths: bool) -> Result<()> {
        let Target::ArchiveDirectory { archive, .. } = &self.target else {
            return Ok(());
        };
        if archive.game.engine != vnlens_engine::Engine::Rugp {
            return Ok(());
        }
        for item in &mut self.items {
            if cancel.load(Ordering::Relaxed) {
                return Err(vnlens_core::Error::Cancelled.into());
            }
            let Target::Entry { archive, index } = &item.target else {
                continue;
            };
            if archive.has_references(*index) {
                // A broken child must not hide its siblings. Keep its navigation
                // route so selecting it reports the original parsing error.
                if let Err(error) = archive.open_references(*index, virtual_paths) {
                    if matches!(
                        error.downcast_ref::<vnlens_core::Error>(),
                        Some(vnlens_core::Error::Cancelled)
                    ) {
                        return Err(error);
                    }
                    tracing::debug!(entry = %item.name, error = %error, "Preparing object references");
                }
                item.container = item.target.archive_hint();
            }
        }
        if cancel.load(Ordering::Relaxed) {
            return Err(vnlens_core::Error::Cancelled.into());
        }
        self.sort();
        Ok(())
    }
}

/// Opens only the selected engine's route. Ordinary files have no archive route.
pub fn open(target: &Target, cancel: &AtomicBool, virtual_paths: bool) -> Result<Option<Folder>> {
    if cancel.load(Ordering::Relaxed) {
        return Err(vnlens_core::Error::Cancelled.into());
    }
    let mut folder = match target {
        Target::Opened => Some(Folder::empty(Target::Opened)),
        Target::Directory(path, game) => {
            let game = game
                .for_directory(path, cancel)
                .with_context(|| format!("Identifying {}", path.display()))?;
            let mut items = Vec::new();
            for entry in game
                .files
                .read_dir(path)
                .with_context(|| format!("Listing {}", path.display()))?
            {
                if cancel.load(Ordering::Relaxed) {
                    return Err(vnlens_core::Error::Cancelled.into());
                }
                let metadata = entry.metadata;
                let target = if metadata.directory {
                    Target::Directory(entry.path, game.clone())
                } else {
                    Target::File(entry.path, game.clone())
                };
                items.push(Item::from_target(target, Some(metadata.len)));
            }
            let mut folder = Folder {
                target: Target::Directory(path.clone(), game.clone()),
                items,
            };
            let files = folder
                .items
                .iter()
                .filter_map(|item| match &item.target {
                    Target::File(path, _) => Some(path.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            for set in game.archive_sets(&files) {
                folder.items.retain(|item| {
                    !matches!(&item.target,
                    Target::File(path, _) if set.members.contains(path))
                });
                folder.items.push(Item::from_set(set, game.clone()));
            }
            folder.sort();
            Some(folder)
        }
        Target::ArchiveDirectory { archive, directory } => {
            Some(Folder::archive(archive.clone(), *directory))
        }
        Target::File(path, game) => {
            MountedArchive::open(path.clone(), virtual_paths, game.clone())?
                .map(|archive| Folder::archive(Arc::new(archive), 0))
        }
        Target::ArchiveSet(set, game) => {
            MountedArchive::open(set.primary.clone(), virtual_paths, game.clone())?
                .map(|archive| Folder::archive(Arc::new(archive), 0))
        }
        Target::Entry { archive, index } => {
            if archive.has_references(*index) {
                archive
                    .open_references(*index, virtual_paths)?
                    .map(|archive| Folder::archive(archive, 0))
            } else {
                if archive.psb_values.contains_key(index)
                    || (!matches!(
                        target.resource_route(&[])?,
                        ResourceRoute::Archive(_) | ResourceRoute::Other(_)
                    ) && !archive.game.supports_psb())
                {
                    return Ok(None);
                }
                let source = {
                    let opened = archive
                        .source
                        .lock()
                        .map_err(|_| anyhow!("Archive reader is unavailable"))?;
                    let entry = opened
                        .archive
                        .entries()
                        .get(*index)
                        .ok_or_else(|| anyhow!("Selected entry no longer exists"))?;
                    opened.archive.open_entry_source(entry)?
                };
                let source = if let Some(source) = source {
                    source
                } else {
                    let bytes: Arc<[u8]> = target.read(false, cancel)?.into();
                    Arc::new(bytes) as Arc<dyn vnlens_io::ReadAt>
                };
                let header = source.read_at(0, usize::try_from(source.len().min(64))?)?;
                let ResourceRoute::Archive(route) = target.resource_route(&header)? else {
                    return Ok(None);
                };
                let archive = MountedArchive::open_nested_source(
                    &archive.paths[*index],
                    source,
                    &route,
                    virtual_paths,
                    archive.game.clone(),
                )?;
                Some(Folder::archive(Arc::new(archive), 0))
            }
        }
    };
    if let Some(folder) = &mut folder {
        folder.prepare_references(cancel, virtual_paths)?;
    }
    Ok(folder)
}

/// Expands selected folders iteratively only for an explicit export request.
pub fn export(
    items: &[Item],
    output: &Path,
    raw: bool,
    cancel: &AtomicBool,
    mut report: impl FnMut(Progress, Option<String>),
) -> Result<Extraction> {
    if let Some(archive) = items.first().and_then(|item| match &item.target {
        Target::Entry { archive, .. } | Target::ArchiveDirectory { archive, .. } => Some(archive),
        _ => None,
    }) {
        let mut indices = Vec::new();
        let same_archive = items.iter().all(|item| match &item.target {
            Target::Entry {
                archive: source,
                index,
            } if Arc::ptr_eq(source, archive) => {
                indices.push(*index);
                true
            }
            Target::ArchiveDirectory {
                archive: source,
                directory,
            } if Arc::ptr_eq(source, archive) => {
                indices.extend(source.descendants(*directory));
                true
            }
            _ => false,
        });
        if same_archive {
            return archive::extract(archive, &indices, output, raw, cancel, report);
        }
    }
    enum Step {
        Visit(Target, String),
        Leave(PathBuf),
    }
    let mut pending: Vec<_> = items
        .iter()
        .rev()
        .map(|item| Step::Visit(item.target.clone(), item.target.export_name()))
        .collect();
    let mut seen = HashSet::new();
    let mut files = Vec::new();
    let mut progress = Progress::default();
    while let Some(step) = pending.pop() {
        let (target, name) = match step {
            Step::Visit(target, name) => (target, name),
            Step::Leave(path) => {
                seen.remove(&path);
                continue;
            }
        };
        if cancel.load(Ordering::Relaxed) {
            return Ok(Extraction {
                progress,
                cancelled: true,
            });
        }
        if let Target::ArchiveSet(set, game) = &target {
            // Grouping is presentation only: disk export keeps every physical
            // member at its original relative path, with no synthetic folder.
            let parent = name.rsplit_once('/').map_or("", |(parent, _)| parent);
            pending.extend(set.members.iter().rev().map(|path| {
                let member = path.file_name().unwrap_or_default().to_string_lossy();
                let relative = if parent.is_empty() {
                    member.into_owned()
                } else {
                    format!("{parent}/{member}")
                };
                Step::Visit(Target::File(path.clone(), game.clone()), relative)
            }));
        } else if let Target::Directory(path, game) = &target {
            let canonical = match game.files.canonicalize(path) {
                Ok(path) => path,
                Err(error) => {
                    progress.failed += 1;
                    progress.completed += 1;
                    progress.total += 1;
                    report(progress, Some(format!("{name}: {error}")));
                    continue;
                }
            };
            if !seen.insert(canonical.clone()) {
                progress.failed += 1;
                progress.completed += 1;
                progress.total += 1;
                report(progress, Some(format!("{name}: directory link cycle")));
                continue;
            }
            pending.push(Step::Leave(canonical));
            match open(&target, cancel, false) {
                Ok(Some(folder)) => pending.extend(
                    folder
                        .items
                        .into_iter()
                        .rev()
                        .map(|item| Step::Visit(item.target, format!("{name}/{}", item.name))),
                ),
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
                    progress.completed += 1;
                    progress.total += 1;
                    report(progress, Some(format!("{name}: {error:#}")));
                }
                _ => {}
            }
        } else if let Target::ArchiveDirectory { archive, directory } = &target {
            files.extend(archive.descendants(*directory).into_iter().map(|index| {
                (
                    Target::Entry {
                        archive: archive.clone(),
                        index,
                    },
                    archive.paths[index].clone(),
                )
            }));
        } else if !matches!(target, Target::Opened) {
            files.push((target, name));
        }
    }
    progress.total += files.len();
    for (target, name) in files {
        if cancel.load(Ordering::Relaxed) {
            return Ok(Extraction {
                progress,
                cancelled: true,
            });
        }
        let result = (|| -> Result<()> {
            if let Some(source) = target.video_source(raw)? {
                let written = vnlens_io::filesystem::write_under_with(output, &name, |file| {
                    use std::io::Write;
                    let mut offset = 0;
                    while offset < source.len() {
                        if cancel.load(Ordering::Relaxed) {
                            return Err(std::io::Error::other(vnlens_core::Error::Cancelled));
                        }
                        let size = (source.len() - offset).min(65536) as usize;
                        file.write_all(&source.read_at(offset, size)?)?;
                        offset += size as u64;
                    }
                    Ok(())
                });
                if cancel.load(Ordering::Relaxed) {
                    return Err(vnlens_core::Error::Cancelled.into());
                }
                written?;
                return Ok(());
            }
            let bytes = target.read(raw, cancel)?;
            if cancel.load(Ordering::Relaxed) {
                return Err(vnlens_core::Error::Cancelled.into());
            }
            vnlens_io::filesystem::write_under(output, &name, &bytes)?;
            Ok(())
        })();
        let error = match result {
            Ok(()) => {
                progress.succeeded += 1;
                None
            }
            Err(error) if matches!(error.downcast_ref(), Some(vnlens_core::Error::Cancelled)) => {
                return Ok(Extraction {
                    progress,
                    cancelled: true,
                });
            }
            Err(error) => {
                progress.failed += 1;
                Some(format!("{name}: {error:#}"))
            }
        };
        progress.completed += 1;
        report(progress, error);
    }
    Ok(Extraction {
        progress,
        cancelled: false,
    })
}

#[cfg(test)]
#[path = "../tests/browser.rs"]
mod tests;
