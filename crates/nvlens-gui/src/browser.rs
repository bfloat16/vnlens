//! Folder navigation shared by disk directories and mounted archive directories.
//! Listing uses filesystem metadata or archive indices; file contents are read
//! only when a file or a nested container is selected.

use crate::archive::{self, Extraction, MountedArchive, Node, Progress};
use anyhow::{Context, Result, anyhow};
use nvlens_core::ResourceKind;
use nvlens_engine::Identification;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Debug)]
pub enum Target {
    /// Virtual root populated only with paths explicitly opened by the user.
    Opened,
    Directory(PathBuf, Arc<Identification>),
    File(PathBuf, Arc<Identification>),
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
    pub fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Opened, Self::Opened) => true,
            (Self::Directory(a, _), Self::Directory(b, _))
            | (Self::File(a, _), Self::File(b, _)) => a == b,
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
            Self::File(path, game) => game.route_path(path).is_some(),
            Self::Entry { archive, index } => {
                archive.game.route(&archive.entries[*index].name).is_some()
            }
            _ => false,
        }
    }
    pub fn read(&self, raw: bool, cancel: &AtomicBool) -> Result<Vec<u8>> {
        if cancel.load(Ordering::Relaxed) {
            return Err(nvlens_core::Error::Cancelled.into());
        }
        match self {
            Self::File(path, _) => {
                std::fs::read(path).with_context(|| format!("Reading {}", path.display()))
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
    pub fn from_path(path: PathBuf) -> Result<Self> {
        let metadata =
            std::fs::metadata(&path).with_context(|| format!("Opening {}", path.display()))?;
        let game = Arc::new(
            nvlens_engine::identify(&path, &AtomicBool::new(false))?.ok_or_else(|| {
                anyhow!("Game engine was not identified; resource processing is disabled")
            })?,
        );
        let target = if metadata.is_dir() {
            Target::Directory(path, game)
        } else {
            Target::File(path, game)
        };
        Ok(Self::from_target(target, Some(metadata.len())))
    }
    fn from_target(target: Target, size: Option<u64>) -> Self {
        let name = target.name();
        let container = target.is_directory() || target.archive_hint();
        let (kind, count) = match &target {
            Target::ArchiveDirectory { archive, directory } => (
                ResourceKind::Archive,
                Some(archive.directories[*directory].items.len()),
            ),
            Target::Entry { archive, index } => (archive.entries[*index].kind, None),
            _ => (ResourceKind::guess_from_name(&name), None),
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
        let items = archive.directories[directory]
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
    fn sort(&mut self) {
        self.items.sort_by(|a, b| {
            b.container
                .cmp(&a.container)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
    }
}

/// Opens only the selected engine's route. Ordinary files have no archive route.
pub fn open(target: &Target, cancel: &AtomicBool, virtual_paths: bool) -> Result<Option<Folder>> {
    if cancel.load(Ordering::Relaxed) {
        return Err(nvlens_core::Error::Cancelled.into());
    }
    match target {
        Target::Opened => Ok(Some(Folder::empty(Target::Opened))),
        Target::Directory(path, game) => {
            let mut items = Vec::new();
            for entry in
                std::fs::read_dir(path).with_context(|| format!("Listing {}", path.display()))?
            {
                if cancel.load(Ordering::Relaxed) {
                    return Err(nvlens_core::Error::Cancelled.into());
                }
                let entry = entry?;
                let metadata = std::fs::metadata(entry.path()).ok();
                let target = if metadata.as_ref().is_some_and(|m| m.is_dir()) {
                    Target::Directory(entry.path(), game.clone())
                } else {
                    Target::File(entry.path(), game.clone())
                };
                items.push(Item::from_target(target, metadata.map(|m| m.len())));
            }
            let mut folder = Folder {
                target: target.clone(),
                items,
            };
            folder.sort();
            Ok(Some(folder))
        }
        Target::ArchiveDirectory { archive, directory } => {
            Ok(Some(Folder::archive(archive.clone(), *directory)))
        }
        Target::File(path, game) => {
            Ok(
                MountedArchive::open(path.clone(), virtual_paths, game.clone())?
                    .map(|archive| Folder::archive(Arc::new(archive), 0)),
            )
        }
        Target::Entry { archive, index } => {
            if archive.game.route(&archive.entries[*index].name).is_none() {
                return Ok(None);
            }
            let bytes = target.read(false, cancel)?;
            Ok(MountedArchive::open_nested(
                &archive.entries[*index].name,
                &bytes,
                virtual_paths,
                archive.game.clone(),
            )?
            .map(|archive| Folder::archive(Arc::new(archive), 0)))
        }
    }
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
        if let Target::Directory(path, _) = &target {
            let canonical = match std::fs::canonicalize(path) {
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
                    if matches!(error.downcast_ref(), Some(nvlens_core::Error::Cancelled)) =>
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
            let bytes = target.read(raw, cancel)?;
            if cancel.load(Ordering::Relaxed) {
                return Err(nvlens_core::Error::Cancelled.into());
            }
            nvlens_io::filesystem::write_under(output, &name, &bytes)?;
            Ok(())
        })();
        let error = match result {
            Ok(()) => {
                progress.succeeded += 1;
                None
            }
            Err(error) if matches!(error.downcast_ref(), Some(nvlens_core::Error::Cancelled)) => {
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;
    use std::fs;
    use std::sync::atomic::AtomicU64;

    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn temp() -> Temp {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "nvlens-browser-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::write(path.join("AdvHD.exe"), []).unwrap();
        fs::write(path.join("Script2.arc"), []).unwrap();
        fs::write(path.join("Graphic.arc"), []).unwrap();
        Temp(path)
    }
    fn fixture(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut index = vec![0; 8];
        BinaryWriter::u32_le(payload.len() as u32, &mut index);
        for unit in name.encode_utf16().chain([0]) {
            let mut word = [0; 2];
            BinaryWriter::u16_le(unit, &mut word);
            index.extend(word);
        }
        let mut bytes = vec![0; 8];
        BinaryWriter::u32_le(1, &mut bytes);
        BinaryWriter::u32_le(index.len() as u32, &mut bytes[4..]);
        bytes.extend(index);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn opened_root_starts_empty() {
        let folder = open(&Target::Opened, &AtomicBool::new(false), false)
            .unwrap()
            .unwrap();
        assert!(matches!(folder.target, Target::Opened));
        assert!(folder.items.is_empty());
    }

    #[test]
    fn standalone_archives_cannot_bypass_engine_identification() {
        let dir = temp();
        for name in ["AdvHD.exe", "Script2.arc", "Graphic.arc"] {
            fs::remove_file(dir.0.join(name)).unwrap();
        }
        let archive = dir.0.join("valid.arc");
        fs::write(&archive, fixture("data.txt", b"contents")).unwrap();
        assert!(Item::from_path(archive).is_err());
        assert!(Item::from_path(dir.0.clone()).is_err());
    }

    #[test]
    fn lists_disk_without_mounting_archives_or_reading_files() {
        nvlens_archive::init();
        let dir = temp();
        let cancel = AtomicBool::new(false);
        let mut invalid = vec![0; 32];
        invalid[..4].copy_from_slice(b"YPF\0");
        fs::write(dir.0.join("broken.arc"), invalid).unwrap();
        fs::write(dir.0.join("note.txt"), b"old").unwrap();
        fs::create_dir(dir.0.join("folder")).unwrap();
        let folder = open(
            &Item::from_path(dir.0.clone()).unwrap().target,
            &cancel,
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(folder.items.len(), 6);
        let archive = folder
            .items
            .iter()
            .find(|item| item.name == "broken.arc")
            .unwrap();
        assert!(archive.container);
        assert!(open(&archive.target, &cancel, false).is_err());
        let file = folder
            .items
            .iter()
            .find(|item| item.name == "note.txt")
            .unwrap();
        fs::write(dir.0.join("note.txt"), b"changed after listing").unwrap();
        let resource = crate::resource::read(&file.target, false, &cancel).unwrap();
        assert_eq!(&*resource.bytes, b"changed after listing");
    }

    #[test]
    fn traverses_disk_archive_directories_and_nested_archives() {
        nvlens_archive::init();
        let dir = temp();
        let cancel = AtomicBool::new(false);
        let inner = fixture("leaf.txt", b"leaf");
        fs::write(dir.0.join("outer.arc"), fixture("nested/inner.arc", &inner)).unwrap();
        let disk = open(
            &Item::from_path(dir.0.clone()).unwrap().target,
            &cancel,
            false,
        )
        .unwrap()
        .unwrap();
        let outer = open(
            &disk
                .items
                .iter()
                .find(|item| item.name == "outer.arc")
                .unwrap()
                .target,
            &cancel,
            false,
        )
        .unwrap()
        .unwrap();
        let nested = open(&outer.items[0].target, &cancel, false)
            .unwrap()
            .unwrap();
        assert!(nested.items[0].container);
        let inner = open(&nested.items[0].target, &cancel, false)
            .unwrap()
            .unwrap();
        assert_eq!(inner.items[0].target.read(false, &cancel).unwrap(), b"leaf");
        assert!(!inner.items[0].container);
    }

    #[test]
    fn disk_export_continues_after_failure_and_honors_cancellation() {
        let dir = temp();
        let cancel = AtomicBool::new(false);
        let missing = dir.0.join("missing.txt");
        let good = dir.0.join("good.txt");
        fs::write(&missing, b"gone").unwrap();
        fs::write(&good, b"ok").unwrap();
        let items = vec![
            Item::from_path(missing.clone()).unwrap(),
            Item::from_path(good).unwrap(),
        ];
        fs::remove_file(missing).unwrap();
        let out = dir.0.join("out");
        let result = export(&items, &out, false, &cancel, |_, _| {}).unwrap();
        assert_eq!((result.progress.succeeded, result.progress.failed), (1, 1));
        assert_eq!(fs::read(out.join("good.txt")).unwrap(), b"ok");
        cancel.store(true, Ordering::Relaxed);
        let result = export(&items, &dir.0.join("cancelled"), false, &cancel, |_, _| {}).unwrap();
        assert!(result.cancelled);
        assert_eq!(result.progress.completed, 0);
        assert!(!dir.0.join("cancelled").exists());
    }
}
