#![allow(clippy::unwrap_used)]

use super::*;
fn game(path: &Path) -> Arc<vnlens_engine::Identification> {
    Arc::new(
        vnlens_engine::identify(path, &AtomicBool::new(false))
            .unwrap()
            .unwrap(),
    )
}
use std::fs;
use std::sync::atomic::AtomicU64;
use std::time::{SystemTime, UNIX_EPOCH};
use vnlens_io::BinaryWriter;

#[test]
fn rugp_navigation_prepares_only_one_layer_and_reuses_children() {
    use crate::browser::{self, Target};
    use vnlens_core::{Archive, ResourceKind};

    struct Graph {
        entries: Vec<Entry>,
        calls: Arc<Mutex<Vec<String>>>,
        cancel: Arc<AtomicBool>,
    }
    fn entry(name: &str) -> Entry {
        Entry {
            name: name.into(),
            offset: 0,
            size: 1,
            kind: ResourceKind::Data,
            packed: None,
        }
    }
    impl Archive for Graph {
        fn entries(&self) -> &[Entry] {
            &self.entries
        }
        fn open_entry(&self, entry: &Entry) -> vnlens_core::Result<std::borrow::Cow<'_, [u8]>> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("read:{}", entry.name));
            Err(vnlens_core::Error::Unsupported(
                "Unrequested payload".into(),
            ))
        }
        fn has_references(&self, entry: &Entry) -> bool {
            entry.name != "media"
        }
        fn open_references(&self, node: &Entry) -> vnlens_core::Result<Option<Box<dyn Archive>>> {
            self.calls.lock().unwrap().push(node.name.clone());
            let entries = match node.name.as_str() {
                "empty" => return Ok(None),
                "empty-index" => Vec::new(),
                "group" => vec![entry("nested")],
                "nested" => vec![entry("deep")],
                "deep" => vec![entry("group")],
                "cancel" => {
                    self.cancel.store(true, Ordering::Relaxed);
                    return Ok(None);
                }
                _ => {
                    return Err(vnlens_core::Error::Corrupt {
                        offset: 0,
                        reason: "Broken child".into(),
                    });
                }
            };
            Ok(Some(Box::new(Self {
                entries,
                calls: self.calls.clone(),
                cancel: self.cancel.clone(),
            })))
        }
    }
    let dir = directory();
    let mut identified = (*game(&dir.0)).clone();
    identified.engine = vnlens_engine::Engine::Rugp;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let cancel = Arc::new(AtomicBool::new(false));
    let mount = |names: &[&str], game| {
        let entries: Vec<_> = names.iter().map(|name| entry(name)).collect();
        let paths: Vec<_> = entries.iter().map(|entry| entry.name.clone()).collect();
        Arc::new(MountedArchive {
            filesystem: false,
            path: dir.0.join("graph"),
            source_path: dir.0.join("graph"),
            references: entries
                .iter()
                .map(|e| AtomicBool::new(e.name != "media"))
                .collect(),
            reference_archives: Arc::default(),
            entries: entries.clone().into(),
            psb_values: Default::default(),
            directories: directories(&paths),
            paths,
            source: Arc::new(Mutex::new(Opened {
                format_tag: "test/graph",
                archive: Box::new(Graph {
                    entries,
                    calls: calls.clone(),
                    cancel: cancel.clone(),
                }),
            })),
            game,
            _backing: None,
        })
    };
    let archive = mount(
        &["empty", "empty-index", "group", "broken", "media"],
        Arc::new(identified),
    );
    let target = Target::ArchiveDirectory {
        archive: archive.clone(),
        directory: 0,
    };
    assert!(calls.lock().unwrap().is_empty());
    let folder = browser::open(&target, &cancel, false).unwrap().unwrap();
    assert_eq!(
        *calls.lock().unwrap(),
        ["broken", "empty", "empty-index", "group"]
    );
    assert_eq!(
        folder
            .items
            .iter()
            .map(|i| (i.name.as_str(), i.container))
            .collect::<Vec<_>>(),
        [
            ("broken", true),
            ("group", true),
            ("empty", false),
            ("empty-index", false),
            ("media", false),
        ]
    );
    let leaf = folder.items.iter().find(|i| i.name == "empty").unwrap();
    assert!(
        browser::open(&leaf.target, &cancel, false)
            .unwrap()
            .is_none()
    );
    assert!(archive.open_references(1, false).unwrap().is_none());
    assert_eq!(calls.lock().unwrap().len(), 4);
    let group = archive.open_references(2, false).unwrap().unwrap();
    let renamed = archive.with_paths(archive.paths.clone()).unwrap();
    assert!(Arc::ptr_eq(
        &group,
        &renamed.open_references(2, false).unwrap().unwrap()
    ));
    let item = folder.items.iter().find(|i| i.name == "group").unwrap();
    assert!(item.can_preview());
    let nested = browser::open(&item.target, &cancel, false)
        .unwrap()
        .unwrap();
    assert_eq!(nested.items.len(), 1);
    assert!(nested.items[0].container);
    assert_eq!(
        *calls.lock().unwrap(),
        ["broken", "empty", "empty-index", "group", "nested"]
    );
    let _ = browser::open(&item.target, &cancel, false)
        .unwrap()
        .unwrap();
    assert_eq!(calls.lock().unwrap().len(), 5);
    let broken = folder.items.iter().find(|i| i.name == "broken").unwrap();
    assert!(
        browser::open(&broken.target, &cancel, false)
            .unwrap_err()
            .to_string()
            .contains("Broken child")
    );

    calls.lock().unwrap().clear();
    let target = Target::ArchiveDirectory {
        archive: mount(&["cancel", "group"], archive.game.clone()),
        directory: 0,
    };
    let error = browser::open(&target, &cancel, false).unwrap_err();
    assert!(matches!(
        error.downcast_ref(),
        Some(vnlens_core::Error::Cancelled)
    ));
    assert_eq!(*calls.lock().unwrap(), ["cancel"]);
    cancel.store(false, Ordering::Relaxed);
    calls.lock().unwrap().clear();
    let target = Target::ArchiveDirectory {
        archive: mount(&["group"], game(&dir.0)),
        directory: 0,
    };
    assert!(
        browser::open(&target, &cancel, false)
            .unwrap()
            .unwrap()
            .items[0]
            .container
    );
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn reference_exports_visit_shared_cycles_once_and_honor_cancellation() {
    struct Graph(Vec<Entry>);
    fn entry(name: &str) -> Entry {
        Entry {
            name: name.into(),
            offset: 0,
            size: 1,
            kind: vnlens_core::ResourceKind::Script,
            packed: None,
        }
    }
    impl vnlens_core::Archive for Graph {
        fn entries(&self) -> &[Entry] {
            &self.0
        }
        fn open_entry(&self, entry: &Entry) -> vnlens_core::Result<std::borrow::Cow<'_, [u8]>> {
            Ok(std::borrow::Cow::Borrowed(if entry.name == "root" {
                b"r"
            } else {
                b"l"
            }))
        }
        fn has_references(&self, entry: &Entry) -> bool {
            entry.name == "root"
        }
        fn open_references(
            &self,
            node: &Entry,
        ) -> vnlens_core::Result<Option<Box<dyn vnlens_core::Archive>>> {
            Ok((node.name == "root").then(|| {
                Box::new(Graph(vec![node.clone(), entry("leaf")])) as Box<dyn vnlens_core::Archive>
            }))
        }
    }
    let dir = directory();
    let entries = vec![entry("root")];
    let archive = MountedArchive {
        filesystem: false,
        path: dir.0.join("graph"),
        source_path: dir.0.join("graph"),
        entries: entries.clone().into(),
        psb_values: Default::default(),
        paths: vec!["root".into()],
        references: vec![AtomicBool::new(true)].into(),
        reference_archives: Arc::default(),
        directories: directories(&["root".into()]),
        source: Arc::new(Mutex::new(Opened {
            format_tag: "test/graph",
            archive: Box::new(Graph(entries)),
        })),
        game: game(&dir.0),
        _backing: None,
    };
    let cancel = AtomicBool::new(false);
    let out = dir.0.join("out");
    let result = extract(&archive, &[0], &out, false, &cancel, |_, _| {}).unwrap();
    assert_eq!(
        (
            result.progress.total,
            result.progress.completed,
            result.progress.succeeded,
            result.progress.failed
        ),
        (3, 3, 2, 0)
    );
    assert_eq!(fs::read(out.join("root")).unwrap(), b"r");
    assert_eq!(fs::read(out.join("leaf")).unwrap(), b"l");
    let out = dir.0.join("cancelled");
    let result = extract(&archive, &[0], &out, false, &cancel, |_, _| {
        cancel.store(true, Ordering::Relaxed)
    })
    .unwrap();
    assert!(result.cancelled);
    assert_eq!(result.progress.completed, 1);
    assert!(!out.join("leaf").exists());
}

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn directory() -> Directory {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "vnlens-gui-{}-{}-{}",
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
    vnlens_archive::init();
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
    vnlens_archive::init();
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
    vnlens_archive::init();
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
fn opens_nested_archives_on_demand_and_removes_temporary_files() -> Result<()> {
    vnlens_archive::init();
    let mut bytes = fixture(&[("leaf.txt", b"leaf")]);
    for _ in 0..24 {
        bytes = fixture(&[("nested.arc", &bytes)]);
    }
    let dir = directory();
    let game = game(&dir.0);
    let ResourceRoute::Archive(route) =
        game.resource_route("root.arc", vnlens_core::ResourceOrigin::File, &bytes)
    else {
        return Err(anyhow!("Missing fixture archive route"));
    };
    let mut opened =
        MountedArchive::open_nested("root.arc", &bytes, &route, false, game.clone()).unwrap();
    let cancelled = AtomicBool::new(false);
    let first_cache = opened._backing.as_ref().unwrap().0.clone();
    for _ in 0..24 {
        assert_eq!(opened.entries[0].name, "nested.arc");
        let bytes = read_entry(&opened.source, 0, false, &cancelled).unwrap();
        opened =
            MountedArchive::open_nested("nested.arc", &bytes, &route, false, game.clone()).unwrap();
    }
    assert!(!first_cache.exists());
    assert_eq!(
        read_entry(&opened.source, 0, false, &cancelled).unwrap(),
        b"leaf"
    );
    let last_cache = opened._backing.as_ref().unwrap().0.clone();
    drop(opened);
    assert!(!last_cache.exists());
    Ok(())
}

#[test]
fn virtual_names_drive_directories_and_exports_without_changing_storage_entries() {
    vnlens_archive::init();
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
