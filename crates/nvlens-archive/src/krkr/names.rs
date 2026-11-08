//! Incremental game-scoped Hxv4 name recovery. Each step reads one requested
//! resource, retains only exact hash matches and never mutates stored entries.
//! Unrecognized image/audio bodies are skipped after a short decoded prefix.
use super::*;
use nvlens_crypto::hash::hxv4 as hashes;
use std::{
    io::Read,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy, Debug, Default)]
pub struct NameProgress {
    pub completed: usize,
    pub total: usize,
    pub resolved: usize,
    pub failed: usize,
}
struct Source {
    path: PathBuf,
    archive: Xp3Archive,
}
/// A background recovery session with independent mappings and decoder state.
/// Call `step` until false; snapshots expose names by original entry index.
pub struct NameRecovery {
    sources: Vec<Source>,
    pending: std::collections::VecDeque<(usize, usize)>,
    directories: BTreeMap<String, Option<String>>,
    files: BTreeMap<String, Option<String>>,
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
fn hex(bytes: &[u8]) -> String {
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
impl NameRecovery {
    /// Mounts only the indices of explicitly routed sibling XP3 files.
    /// Unreadable siblings are reported individually and other sources continue.
    pub fn open(inputs: &[(PathBuf, ArchiveOptions)], cancel: &AtomicBool) -> Result<Self> {
        check(cancel)?;
        let mut this = Self {
            sources: Vec::new(),
            pending: Default::default(),
            directories: Default::default(),
            files: Default::default(),
            context_files: Default::default(),
            progress: Default::default(),
            revision: 0,
            errors: Vec::new(),
        };
        for (path, options) in inputs {
            check(cancel)?;
            match ArcView::open(path)
                .map_err(Error::from)
                .and_then(|v| Xp3Archive::open(&Arc::new(v), options))
            {
                Ok(archive) => {
                    let source = this.sources.len();
                    for (index, entry) in archive.entries.iter().enumerate() {
                        this.pending.push_back((source, index));
                        if let Some((dir, name)) = hashed(&entry.name) {
                            this.directories.entry(dir.into()).or_default();
                            this.files.entry(name.into()).or_default();
                        }
                    }
                    this.sources.push(Source {
                        path: path.clone(),
                        archive,
                    });
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
        let mut progress = self.progress;
        progress.resolved = self
            .sources
            .iter()
            .flat_map(|s| &s.archive.entries)
            .filter(|e| {
                hashed(&e.name)
                    .is_some_and(|(_, file)| self.files.get(file).is_some_and(Option::is_some))
            })
            .count();
        progress
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
            .and_then(Option::as_deref)
            .unwrap_or(file);
        if dir.is_empty() {
            file.into()
        } else {
            format!("{dir}/{file}")
        }
    }
    fn candidate(&mut self, raw: &str) {
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
            self.match_directory(&spelling);
            if !spelling.is_empty() {
                self.match_directory(&format!("{}/", spelling.trim_end_matches('/')));
            }
            for (pos, _) in spelling.match_indices('/') {
                self.match_directory(&spelling[..=pos]);
                self.match_directory(&spelling[..pos]);
            }
            if let Some(name) = spelling.rsplit('/').next().filter(|s| !s.is_empty()) {
                let hash = hex(&hashes::filename(name, "xp3hnp"));
                if let Some(slot) = self.files.get_mut(&hash)
                    && slot.is_none()
                {
                    *slot = Some(name.into());
                    self.revision += 1;
                }
            }
        }
    }
    fn match_directory(&mut self, name: &str) {
        let hash = hex(&hashes::directory(name, "xp3hnp"));
        if let Some(slot) = self.directories.get_mut(&hash)
            && slot.is_none()
        {
            *slot = Some(name.into());
            self.revision += 1;
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
        let entry = &self.sources[source].archive.entries[index];
        let name = self.resolve(&entry.name);
        let result = (|| {
            let archive = &self.sources[source].archive;
            let prefix = archive.prefix(entry, 16, cancel)?;
            let known = prefix.starts_with(b"TJS2100\0")
                || prefix.starts_with(b"PSB\0")
                || nvlens_script::mdf::is_mdf(&prefix)
                || prefix.starts_with(&[0xfe, 0xfe])
                || prefix.starts_with(&[0xff, 0xfe]);
            let text = prefix
                .iter()
                .all(|&b| b >= 32 || matches!(b, b'\r' | b'\n' | b'\t'));
            if !known && !text {
                return Ok(Vec::new());
            }
            let bytes = archive.read_cancellable(entry, cancel)?;
            nvlens_script::krkr::name_candidates(&bytes, &name, cancel)
        })();
        match result {
            Ok(candidates) => {
                for candidate in candidates {
                    check(cancel)?;
                    self.candidate(&candidate);
                }
            }
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
        if name
            .rsplit('/')
            .next()
            .is_some_and(|name| matches!(name, "!scnlist.txt" | "sysse.ini"))
        {
            self.context_files.insert((source, index));
        }
        if self.pending.is_empty() {
            for (s, source) in self.sources.iter().enumerate() {
                for (i, entry) in source.archive.entries.iter().enumerate() {
                    if self
                        .resolve(&entry.name)
                        .rsplit('/')
                        .next()
                        .is_some_and(|name| matches!(name, "!scnlist.txt" | "sysse.ini"))
                        && self.context_files.insert((s, i))
                    {
                        self.pending.push_back((s, i));
                        self.progress.total += 1;
                    }
                }
            }
        }
        Ok(true)
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
            if let (Some((key, flag)), Some(filter)) = (record.filter, &self.filter) {
                filter.apply_entry(key, flag, out.len() as u64, &mut part);
            }
            out.extend(part);
        }
        Ok(out)
    }
    pub(super) fn read_cancellable(&self, entry: &Entry, cancel: &AtomicBool) -> Result<Vec<u8>> {
        let record = self.record(entry)?;
        let mut out = Vec::new();
        for segment in &record.segments {
            let raw = self.view.slice(segment.offset, segment.stored)?;
            let mut reader: Box<dyn Read + '_> = if segment.compressed {
                Box::new(zlib::decoder(raw))
            } else {
                Box::new(raw)
            };
            let start = out.len();
            let mut block = [0; 65536];
            loop {
                check(cancel)?;
                let read = reader.read(&mut block)?;
                if read == 0 {
                    break;
                }
                if (out.len() - start) as u64 + read as u64 > segment.size {
                    return Err(corrupt(segment.offset, "XP3 decoded segment exceeds size"));
                }
                if let (Some((key, flag)), Some(filter)) = (record.filter, &self.filter) {
                    filter.apply_entry(key, flag, out.len() as u64, &mut block[..read]);
                }
                out.extend_from_slice(&block[..read]);
            }
            if (out.len() - start) as u64 != segment.size {
                return Err(corrupt(
                    segment.offset,
                    "XP3 decoded segment length mismatch",
                ));
            }
        }
        if record
            .adler
            .is_some_and(|sum| adler32::checksum(&out) != sum)
        {
            return Err(corrupt(entry.offset, "XP3 plaintext checksum mismatch"));
        }
        Ok(out)
    }
}
