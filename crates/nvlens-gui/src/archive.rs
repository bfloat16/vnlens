//! Background archive operations shared by the desktop views.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use anyhow::{Context, Result, anyhow, bail};
use nvlens_core::{Catalog, Entry, Opened};

#[derive(Debug)]
pub struct MountedArchive {
    pub path: PathBuf,
    pub entries: Arc<[Entry]>,
    pub paths: Vec<String>,
    pub source: Arc<Mutex<Opened>>,
    pub directories: Vec<Directory>,
    pub game: Arc<nvlens_engine::Identification>,
    // Keep temporary nested sources alive until all mapped readers are dropped.
    _backing: Option<TemporaryArchive>,
}

impl MountedArchive {
    /// Opens the index and, only when requested, virtual-path metadata.
    /// The UI never locks the source on its event thread.
    pub fn open(
        path: PathBuf,
        virtual_paths: bool,
        game: Arc<nvlens_engine::Identification>,
    ) -> Result<Option<Self>> {
        let Some(route) = game.route_path(&path) else {
            return Ok(None);
        };
        let opened = Catalog::load()
            .open(&path, &route)
            .with_context(|| format!("Opening {} with {:?}", path.display(), game.engine))?;
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
        Ok(Some(Self {
            path,
            directories: directories(&paths),
            entries: opened.archive.entries().into(),
            paths,
            source: Arc::new(Mutex::new(opened)),
            game,
            _backing: None,
        }))
    }

    /// Materializes only the selected nested container, preserving its extension.
    pub fn open_nested(
        name: &str,
        bytes: &[u8],
        virtual_paths: bool,
        game: Arc<nvlens_engine::Identification>,
    ) -> Result<Option<Self>> {
        if game.route(name).is_none() {
            return Ok(None);
        }
        let backing = TemporaryArchive::new()?;
        let file_name = name.rsplit(['/', '\\']).next().unwrap_or("archive");
        let path = nvlens_io::filesystem::write_under(&backing.0, file_name, bytes)?;
        let Some(mut opened) = Self::open(path, virtual_paths, game)? else {
            return Ok(None);
        };
        opened.path = PathBuf::from(name);
        opened._backing = Some(backing);
        Ok(Some(opened))
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
                    directories.push(Directory::default());
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
                "nvlens-nested-{}-{time}-{sequence}",
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
        return Err(nvlens_core::Error::Cancelled.into());
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

/// Extracts only requested indices, preserving per-entry failures and cancellation.
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
    for &index in indices {
        if cancelled.load(Ordering::Relaxed) {
            return Ok(Extraction {
                progress,
                cancelled: true,
            });
        }
        let Some(entry) = opened.archive.entries().get(index) else {
            bail!("Selected entry no longer exists");
        };
        let result = (|| -> Result<()> {
            let bytes = if raw {
                opened.archive.open_entry_raw(entry)?
            } else {
                opened.archive.open_entry(entry)?
            };
            if cancelled.load(Ordering::Relaxed) {
                return Err(nvlens_core::Error::Cancelled.into());
            }
            nvlens_io::filesystem::write_under(output, &archive.paths[index], &bytes)?;
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
                Some(format!(
                    "{} [{} at 0x{:x}]: {error:#}",
                    entry.name, opened.format_tag, entry.offset
                ))
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
    fn game(path: &Path) -> Arc<nvlens_engine::Identification> {
        Arc::new(
            nvlens_engine::identify(path, &AtomicBool::new(false))
                .unwrap()
                .unwrap(),
        )
    }
    use nvlens_io::BinaryWriter;
    use std::fs;
    use std::sync::atomic::AtomicU64;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn directory() -> Directory {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "nvlens-gui-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::write(path.join("AdvHD.exe"), []).unwrap();
        fs::write(path.join("Script2.arc"), []).unwrap();
        fs::write(path.join("Graphic.arc"), []).unwrap();
        Directory(path)
    }
    fn fixture(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut body = Vec::new();
        for (name, bytes) in entries {
            let mut record = [0; 8];
            BinaryWriter::u32_le(bytes.len() as u32, &mut record);
            BinaryWriter::u32_le(body.len() as u32, &mut record[4..]);
            index.extend_from_slice(&record);
            for unit in name.encode_utf16().chain([0]) {
                let mut encoded = [0; 2];
                BinaryWriter::u16_le(unit, &mut encoded);
                index.extend_from_slice(&encoded);
            }
            body.extend_from_slice(bytes);
        }
        let mut bytes = vec![0; 8];
        BinaryWriter::u32_le(entries.len() as u32, &mut bytes);
        BinaryWriter::u32_le(index.len() as u32, &mut bytes[4..]);
        bytes.extend(index);
        bytes.extend(body);
        bytes
    }
    #[test]
    fn mounts_lazily_extracts_raw_and_continues_after_errors() {
        nvlens_archive::init();
        let dir = directory();
        let path = dir.0.join("test.arc");
        fs::write(&path, fixture(&[("bad.psp", &[1]), ("good.txt", b"ok")])).unwrap();
        let archive = MountedArchive::open(path, false, game(&dir.0))
            .unwrap()
            .unwrap();
        assert_eq!(archive.entries.len(), 2);
        let cancelled = AtomicBool::new(false);
        assert_eq!(
            read_entry(&archive.source, 1, false, &cancelled).unwrap(),
            b"ok"
        );
        let out = dir.0.join("out");
        let mut errors = vec![];
        let result = extract(&archive, &[0, 1], &out, false, &cancelled, |_, e| {
            errors.extend(e)
        })
        .unwrap();
        assert_eq!((result.progress.succeeded, result.progress.failed), (1, 1));
        assert!(errors[0].contains("bad.psp"));
        assert_eq!(fs::read(out.join("good.txt")).unwrap(), b"ok");
        let result = extract(&archive, &[0], &out, true, &cancelled, |_, _| {}).unwrap();
        assert_eq!(result.progress.succeeded, 1);
        assert_eq!(fs::read(out.join("bad.psp")).unwrap(), [1]);
    }
    #[test]
    fn maps_names_and_cancels_between_entries() {
        nvlens_archive::init();
        let dir = directory();
        let path = dir.0.join("names.arc");
        fs::write(
            &path,
            fixture(&[("../outside.bin", b"safe"), ("NUL.txt", b"device")]),
        )
        .unwrap();
        let archive = MountedArchive::open(path, false, game(&dir.0))
            .unwrap()
            .unwrap();
        let out = dir.0.join("out");
        let cancelled = AtomicBool::new(false);
        let result = extract(&archive, &[0, 1], &out, false, &cancelled, |_, _| {
            cancelled.store(true, Ordering::Relaxed)
        })
        .unwrap();
        assert!(result.cancelled);
        assert_eq!(result.progress.completed, 1);
        assert_eq!(fs::read(out.join("%2E%2E/outside.bin")).unwrap(), b"safe");
        assert!(!dir.0.join("outside.bin").exists());
        assert!(!out.join("%4EUL.txt").exists());
        assert!(read_entry(&archive.source, 1, false, &cancelled).is_err());
        cancelled.store(false, Ordering::Relaxed);
        extract(&archive, &[1], &out, false, &cancelled, |_, _| {}).unwrap();
        assert_eq!(fs::read(out.join("%4EUL.txt")).unwrap(), b"device");
    }

    #[test]
    fn browses_deep_directories_without_reading_contents() {
        nvlens_archive::init();
        let dir = directory();
        let path = dir.0.join("deep.arc");
        let name = format!("{}broken.psp", "folder/".repeat(2048));
        fs::write(
            &path,
            fixture(&[(&name, &[1]), ("folder/other.txt", b"ok")]),
        )
        .unwrap();
        let archive = MountedArchive::open(path, false, game(&dir.0))
            .unwrap()
            .unwrap();
        assert_eq!(archive.directories.len(), 2049);
        let mut node = 0;
        for _ in 0..2048 {
            let next = archive.directories[node]
                .items
                .iter()
                .find_map(|item| match item.node {
                    Node::Directory(next) => Some(next),
                    Node::Entry(_) => None,
                })
                .unwrap();
            node = next;
        }
        assert_eq!(archive.descendants(node), vec![0]);
        assert_eq!(archive.descendants(0), vec![0, 1]);
    }

    #[test]
    fn opens_nested_archives_on_demand_and_removes_temporary_files() {
        nvlens_archive::init();
        let mut bytes = fixture(&[("leaf.txt", b"leaf")]);
        for _ in 0..24 {
            bytes = fixture(&[("nested.arc", &bytes)]);
        }
        let dir = directory();
        let game = game(&dir.0);
        let mut opened = MountedArchive::open_nested("root.arc", &bytes, false, game.clone())
            .unwrap()
            .unwrap();
        let cancelled = AtomicBool::new(false);
        let first_cache = opened._backing.as_ref().unwrap().0.clone();
        for _ in 0..24 {
            assert_eq!(opened.entries[0].name, "nested.arc");
            let bytes = read_entry(&opened.source, 0, false, &cancelled).unwrap();
            opened = MountedArchive::open_nested("nested.arc", &bytes, false, game.clone())
                .unwrap()
                .unwrap();
        }
        assert!(!first_cache.exists());
        assert_eq!(
            read_entry(&opened.source, 0, false, &cancelled).unwrap(),
            b"leaf"
        );
        let last_cache = opened._backing.as_ref().unwrap().0.clone();
        drop(opened);
        assert!(!last_cache.exists());
    }

    #[test]
    fn virtual_names_drive_directories_and_exports_without_changing_storage_entries() {
        nvlens_archive::init();
        let dir = directory();
        let path = dir.0.join("mapped.arc");
        fs::write(&path, fixture(&[("bytecode.bin", b"contents")])).unwrap();
        let mut archive = MountedArchive::open(path, false, game(&dir.0))
            .unwrap()
            .unwrap();
        archive.paths[0] = "story/chapter/main.yst".into();
        archive.directories = directories(&archive.paths);
        assert_eq!(archive.entries[0].name, "bytecode.bin");
        assert_eq!(archive.directories[0].items[0].name, "story");
        assert_eq!(archive.descendants(0), [0]);
        let output = dir.0.join("out");
        extract(
            &archive,
            &[0],
            &output,
            false,
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        assert_eq!(
            fs::read(output.join("story/chapter/main.yst")).unwrap(),
            b"contents"
        );
        assert!(!output.join("bytecode.bin").exists());
    }

    /// NVLENS_YURIS_GAME=<game> cargo test -p nvlens-gui validates_game_virtual_paths -- --ignored --nocapture
    #[test]
    #[ignore = "Requires NVLENS_YURIS_GAME; validates virtual browsing and export without a window"]
    fn validates_game_virtual_paths() -> Result<()> {
        nvlens_archive::init();
        nvlens_script::init();
        let root = PathBuf::from(
            std::env::var_os("NVLENS_YURIS_GAME")
                .ok_or_else(|| anyhow!("Set NVLENS_YURIS_GAME"))?,
        );
        let physical = MountedArchive::open(root.join("pac/Scripts.ypf"), false, game(&root))?
            .ok_or_else(|| anyhow!("Archive not recognized"))?;
        let virtual_archive = Arc::new(
            MountedArchive::open(root.join("pac/Scripts.ypf"), true, game(&root))?
                .ok_or_else(|| anyhow!("Archive not recognized"))?,
        );
        assert_eq!(physical.entries.len(), virtual_archive.entries.len());
        let mut mapped = 0;
        for (index, (entry, original)) in virtual_archive
            .entries
            .iter()
            .zip(physical.entries.iter())
            .enumerate()
        {
            assert_eq!(entry.name, original.name);
            assert_eq!((entry.offset, entry.size), (original.offset, original.size));
            assert_eq!(physical.paths[index], original.name);
            mapped += usize::from(virtual_archive.paths[index] != physical.paths[index]);
        }
        let mut descendants = virtual_archive.descendants(0);
        descendants.sort_unstable();
        assert_eq!(descendants, (0..physical.entries.len()).collect::<Vec<_>>());
        let index = physical
            .entries
            .iter()
            .position(|entry| entry.name.replace('\\', "/") == "ysbin/yst00003.ybn")
            .ok_or_else(|| anyhow!("Expected script not found"))?;
        assert_eq!(
            virtual_archive.paths[index].replace('\\', "/"),
            "data/script/eris/es_charname.yst"
        );
        let target = crate::browser::Target::Entry {
            archive: virtual_archive.clone(),
            index,
        };
        assert_eq!(target.name(), "es_charname.yst");
        assert_eq!(target.export_name(), virtual_archive.paths[index]);
        let cancelled = AtomicBool::new(false);
        let resource = crate::resource::read(&target, false, &cancelled)?;
        assert_eq!(
            &*resource.bytes,
            read_entry(&physical.source, index, false, &cancelled)?
        );
        assert_eq!(
            resource.script.as_ref().map(|s| s.instructions.len()),
            Some(83)
        );
        let output = directory();
        let result = crate::browser::export(
            &[crate::browser::Item {
                name: target.name(),
                target,
                kind: nvlens_core::ResourceKind::Script,
                size: None,
                count: None,
                container: false,
            }],
            &output.0,
            false,
            &cancelled,
            |_, _| {},
        )?;
        assert_eq!(result.progress.succeeded, 1);
        assert_eq!(
            fs::read(output.0.join("data/script/eris/es_charname.yst"))?,
            &*resource.bytes
        );
        println!(
            "Validated {mapped} virtual script paths across {} entries, original index identities, preview and export",
            physical.entries.len()
        );
        Ok(())
    }
}
