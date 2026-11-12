//! Game-scoped Hxv4 name recovery. Independent readers and hash workers retain
//! only exact matches; the coordinator never mutates stored archive entries.
//! Unrecognized image/audio bodies are skipped after a short decoded prefix.
mod parallel;
use super::*;
use std::{
    io::Read,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_crypto::hash::hxv4 as hashes;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NameProgress {
    pub completed: usize,
    pub total: usize,
    pub resolved: usize,
    pub failed: usize,
}
struct Source {
    path: PathBuf,
    options: ArchiveOptions,
    archive: Xp3Archive,
}
#[derive(Default)]
struct FileName {
    name: Option<String>,
    entries: Vec<(usize, usize)>,
}
/// A background recovery session with independent mappings and decoder state.
/// Call `run` for parallel recovery or `step` until false; snapshots expose
/// names by original entry index.
pub struct NameRecovery {
    sources: Vec<Arc<Source>>,
    pending: std::collections::VecDeque<(usize, usize)>,
    directories: BTreeMap<String, Option<String>>,
    files: BTreeMap<String, FileName>,
    scanned: Vec<Vec<bool>>,
    context_files: BTreeSet<(usize, usize)>,
    progress: NameProgress,
    revision: u64,
    errors: Vec<String>,
}
impl std::fmt::Debug for NameRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NameRecovery")
            .field("progress", &self.progress)
            .finish_non_exhaustive()
    }
}
fn check(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}
fn hashed(path: &str) -> Option<(&str, &str)> {
    let (dir, name) = path.split_once('/')?;
    (dir.len() == 16
        && name.len() == 64
        && dir
            .bytes()
            .chain(name.bytes())
            .all(|b| b.is_ascii_hexdigit()))
    .then_some((dir, name))
}
fn contextual(name: &str) -> bool {
    let leaf = name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase();
    leaf == "sysse.ini"
        || leaf.ends_with(".txt")
        || leaf.ends_with(".stand")
        || leaf.ends_with(".stage")
}
impl NameRecovery {
    /// Mounts only the indices of explicitly routed sibling XP3 files.
    /// Unreadable siblings are reported individually and other sources continue.
    pub fn open(inputs: &[(PathBuf, ArchiveOptions)], cancel: &AtomicBool) -> Result<Self> {
        Self::open_in(inputs, &Arc::new(vnlens_io::FileSystem::default()), cancel)
    }

    /// Opens name-recovery sources through their identified game's overlay.
    pub fn open_in(
        inputs: &[(PathBuf, ArchiveOptions)],
        files: &Arc<vnlens_io::FileSystem>,
        cancel: &AtomicBool,
    ) -> Result<Self> {
        check(cancel)?;
        let mut this = Self {
            sources: Vec::new(),
            pending: Default::default(),
            directories: Default::default(),
            files: Default::default(),
            scanned: Default::default(),
            context_files: Default::default(),
            progress: Default::default(),
            revision: 0,
            errors: Vec::new(),
        };
        for (path, options) in inputs {
            check(cancel)?;
            match files
                .open(path)
                .map_err(Error::from)
                .and_then(|v| Xp3Archive::open(&Arc::new(v), options))
            {
                Ok(archive) => {
                    let source = this.sources.len();
                    for (index, entry) in archive.entries.iter().enumerate() {
                        this.pending.push_back((source, index));
                        if let Some((dir, name)) = hashed(&entry.name) {
                            this.directories.entry(dir.into()).or_default();
                            this.files
                                .entry(name.into())
                                .or_default()
                                .entries
                                .push((source, index));
                        }
                    }
                    this.scanned.push(vec![false; archive.entries.len()]);
                    this.sources.push(Arc::new(Source {
                        path: path.clone(),
                        options: options.clone(),
                        archive,
                    }));
                }
                Err(error) => {
                    this.progress.failed += 1;
                    this.errors.push(format!("{}: {error}", path.display()));
                }
            }
        }
        this.progress.total = this.pending.len();
        for seed in ["/", "startup.tjs", "!scnlist.txt"] {
            this.candidate(seed);
        }
        Ok(this)
    }
    pub fn progress(&self) -> NameProgress {
        self.progress
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn take_errors(&mut self) -> Vec<String> {
        std::mem::take(&mut self.errors)
    }
    pub fn paths(&self) -> BTreeMap<PathBuf, Vec<String>> {
        self.sources
            .iter()
            .map(|s| {
                (
                    s.path.clone(),
                    s.archive
                        .entries
                        .iter()
                        .map(|e| self.resolve(&e.name))
                        .collect(),
                )
            })
            .collect()
    }
    fn resolve(&self, path: &str) -> String {
        let Some((dir, file)) = hashed(path) else {
            return path.into();
        };
        let dir = self
            .directories
            .get(dir)
            .and_then(Option::as_deref)
            .unwrap_or(dir)
            .trim_end_matches('/');
        let file = self
            .files
            .get(file)
            .and_then(|file| file.name.as_deref())
            .unwrap_or(file);
        if dir.is_empty() {
            file.into()
        } else {
            format!("{dir}/{file}")
        }
    }
    fn candidate(&mut self, raw: &str) {
        let mut matches = Matches::default();
        candidates(raw, |directory, hash, name| {
            let known = if directory {
                self.directories.contains_key(&hash)
            } else {
                self.files.contains_key(&hash)
            };
            if known {
                matches.insert(directory, hash, name);
            }
        });
        self.apply(matches);
    }
    fn apply(&mut self, matches: Matches) {
        for (hash, name) in matches.directories {
            if let Some(slot) = self.directories.get_mut(&hash)
                && slot.is_none()
            {
                *slot = Some(name);
                self.revision += 1;
            }
        }
        for (hash, name) in matches.files {
            if let Some(slot) = self.files.get_mut(&hash)
                && slot.name.is_none()
            {
                if contextual(&name) {
                    for &(source, index) in &slot.entries {
                        if self.scanned[source][index] && self.context_files.insert((source, index))
                        {
                            self.pending.push_front((source, index));
                            self.progress.total += 1;
                        }
                    }
                }
                self.progress.resolved += slot.entries.len();
                slot.name = Some(name);
                self.revision += 1;
            }
        }
    }
    /// Processes one resource with cancellation between source/decoder chunks.
    /// Returns false at a fixed point. Per-resource errors are retained and
    /// counted, while cancellation propagates immediately.
    pub fn step(&mut self, cancel: &AtomicBool) -> Result<bool> {
        check(cancel)?;
        let Some((source, index)) = self.pending.pop_front() else {
            return Ok(false);
        };
        let name = self.resolve(&self.sources[source].archive.entries[index].name);
        let result = self.sources[source].find(index, &name, cancel, |directory, hash| {
            if directory {
                self.directories.contains_key(hash)
            } else {
                self.files.contains_key(hash)
            }
        });
        self.complete(source, index, &name, result)?;
        if self.pending.is_empty() {
            self.requeue(cancel)?;
        }
        Ok(true)
    }
    fn complete(
        &mut self,
        source: usize,
        index: usize,
        name: &str,
        result: Result<Matches>,
    ) -> Result<()> {
        match result {
            Ok(matches) => self.apply(matches),
            Err(Error::Cancelled) => return Err(Error::Cancelled),
            Err(error) => {
                self.progress.failed += 1;
                self.errors.push(format!(
                    "{} > {name}: {error}",
                    self.sources[source].path.display()
                ));
            }
        }
        self.progress.completed += 1;
        self.scanned[source][index] = true;
        if contextual(name) {
            self.context_files.insert((source, index));
        } else if contextual(&self.resolve(&self.sources[source].archive.entries[index].name))
            && self.context_files.insert((source, index))
        {
            // A parallel reader may have started before another job supplied
            // this entry's name. Revisit it with the newly available context.
            self.pending.push_front((source, index));
            self.progress.total += 1;
        }
        Ok(())
    }
    fn requeue(&mut self, cancel: &AtomicBool) -> Result<()> {
        for (s, source) in self.sources.iter().enumerate() {
            check(cancel)?;
            for (i, entry) in source.archive.entries.iter().enumerate() {
                check(cancel)?;
                if contextual(&self.resolve(&entry.name)) && self.context_files.insert((s, i)) {
                    self.pending.push_back((s, i));
                    self.progress.total += 1;
                }
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct Matches {
    directories: BTreeMap<String, String>,
    files: BTreeMap<String, String>,
}
impl Matches {
    fn insert(&mut self, directory: bool, hash: String, name: &str) {
        let found = if directory {
            &mut self.directories
        } else {
            &mut self.files
        };
        found.entry(hash).or_insert_with(|| name.into());
    }
}
fn candidates(raw: &str, mut accept: impl FnMut(bool, String, &str)) {
    let raw = raw.trim().trim_matches('\0').replace('\\', "/");
    if raw.is_empty() || raw.chars().any(char::is_control) {
        return;
    }
    let mut value = raw.as_str();
    if let Some((_, tail)) = value.split_once("://./") {
        value = tail;
    } else if let Some((_, tail)) = value.split_once("://") {
        value = tail;
    }
    if let Some((_, tail)) = value.rsplit_once('>') {
        value = tail;
    }
    value = value.trim_start_matches("./").trim_start_matches('/');
    for spelling in [value.to_owned(), value.to_lowercase()] {
        // Full directory strings and every literal prefix are independently
        // validated. No arbitrary directory/file Cartesian product is built.
        accept(
            true,
            hex(&hashes::directory(&spelling, "xp3hnp")),
            &spelling,
        );
        if !spelling.is_empty() {
            let directory = format!("{}/", spelling.trim_end_matches('/'));
            accept(
                true,
                hex(&hashes::directory(&directory, "xp3hnp")),
                &directory,
            );
        }
        for (pos, _) in spelling.match_indices('/') {
            for directory in [&spelling[..=pos], &spelling[..pos]] {
                accept(
                    true,
                    hex(&hashes::directory(directory, "xp3hnp")),
                    directory,
                );
            }
        }
        if let Some(name) = spelling.rsplit('/').next().filter(|s| !s.is_empty()) {
            accept(false, hex(&hashes::filename(name, "xp3hnp")), name);
        }
    }
}
impl Source {
    fn find(
        &self,
        index: usize,
        name: &str,
        cancel: &AtomicBool,
        known: impl Fn(bool, &str) -> bool,
    ) -> Result<Matches> {
        let mut matches = Matches::default();
        for value in self.scan(index, name, cancel)? {
            check(cancel)?;
            candidates(&value, |directory, hash, name| {
                if known(directory, &hash) {
                    matches.insert(directory, hash, name);
                }
            });
        }
        Ok(matches)
    }
    fn scan(&self, index: usize, name: &str, cancel: &AtomicBool) -> Result<Vec<String>> {
        check(cancel)?;
        let archive = &self.archive;
        let entry = &archive.entries[index];
        let prefix = archive.prefix(entry, 16, cancel)?;
        let known = prefix.starts_with(b"TJS2100\0")
            || prefix.starts_with(b"PSB\0")
            || vnlens_middleware::mdf::is_mdf(&prefix)
            || prefix.starts_with(&[0xfe, 0xfe])
            || prefix.starts_with(&[0xff, 0xfe]);
        let text = prefix
            .iter()
            .all(|&b| b >= 32 || matches!(b, b'\r' | b'\n' | b'\t'));
        if !known && !text {
            return Ok(Vec::new());
        }
        let bytes = archive.read_cancellable(entry, cancel)?;
        if prefix.starts_with(b"PSB\0") || vnlens_middleware::mdf::is_mdf(&prefix) {
            let bytes: Arc<[u8]> = bytes.into();
            let file = vnlens_middleware::psb::PsbFile::open_configured(
                Arc::new(bytes),
                name,
                &self.options,
                Some(cancel),
            )?;
            vnlens_script::krkr::psb_name_candidates(&file.document, cancel)
        } else {
            vnlens_script::krkr::name_candidates(&bytes, name, cancel)
        }
    }
}
impl Xp3Archive {
    fn prefix(&self, entry: &Entry, length: usize, cancel: &AtomicBool) -> Result<Vec<u8>> {
        let record = self.record(entry)?;
        let mut out = Vec::new();
        for segment in &record.segments {
            check(cancel)?;
            let count = length
                .saturating_sub(out.len())
                .min(usize::try_from(segment.size).unwrap_or(usize::MAX));
            if count == 0 {
                break;
            }
            let raw = self.view.slice(segment.offset, segment.stored)?;
            let mut part = Vec::new();
            if segment.compressed {
                zlib::decoder(raw)
                    .take(count as u64)
                    .read_to_end(&mut part)?;
            } else {
                part.extend_from_slice(&raw[..count]);
            }
            self.apply_filter(record, out.len() as u64, &mut part);
            out.extend(part);
        }
        Ok(out)
    }
}
