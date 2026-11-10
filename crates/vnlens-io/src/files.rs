//! Game-scoped embedded files overlaid on a physical directory. Metadata and
//! directory listings never open payloads; views materialize only requested files.
use crate::{ArcView, ReadAt};
use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug)]
pub struct FileMetadata {
    pub len: u64,
    pub directory: bool,
}
#[derive(Clone, Debug)]
pub struct DirectoryEntry {
    pub path: PathBuf,
    pub metadata: FileMetadata,
}
struct Embedded {
    path: PathBuf,
    source: Arc<dyn ReadAt>,
    bytes: Mutex<Option<Arc<[u8]>>>,
}
#[derive(Clone, Default)]
pub struct FileSystem {
    embedded: BTreeMap<String, Arc<Embedded>>,
}
impl std::fmt::Debug for FileSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSystem")
            .field("embedded_files", &self.embedded.len())
            .finish()
    }
}
fn key(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches("//?/")
        .trim_end_matches('/')
        .to_lowercase()
}
impl FileSystem {
    /// Adds a virtual file using its original path. Duplicate virtual sources
    /// are ambiguous; a virtual file takes precedence over a disk copy.
    pub fn insert(&mut self, path: PathBuf, source: Arc<dyn ReadAt>) -> io::Result<()> {
        let name = key(&path);
        if self.embedded.contains_key(&name) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Conflicting embedded file paths",
            ));
        }
        self.embedded.insert(
            name,
            Arc::new(Embedded {
                path,
                source,
                bytes: Mutex::new(None),
            }),
        );
        Ok(())
    }
    pub fn metadata(&self, path: &Path) -> io::Result<FileMetadata> {
        let name = key(path);
        if let Some(file) = self.embedded.get(&name) {
            return Ok(FileMetadata {
                len: file.source.len(),
                directory: false,
            });
        }
        if self
            .embedded
            .keys()
            .any(|file| file.starts_with(&format!("{name}/")))
        {
            return Ok(FileMetadata {
                len: 0,
                directory: true,
            });
        }
        std::fs::metadata(path).map(|m| FileMetadata {
            len: m.len(),
            directory: m.is_dir(),
        })
    }
    #[must_use]
    pub fn is_file(&self, path: &Path) -> bool {
        self.metadata(path).is_ok_and(|m| !m.directory)
    }
    #[must_use]
    pub fn is_dir(&self, path: &Path) -> bool {
        self.metadata(path).is_ok_and(|m| m.directory)
    }

    /// Merges physical and virtual immediate children without reading payloads.
    pub fn read_dir(&self, path: &Path) -> io::Result<Vec<DirectoryEntry>> {
        let mut entries = BTreeMap::new();
        match std::fs::read_dir(path) {
            Ok(directory) => {
                for item in directory {
                    let item = item?;
                    let metadata = item.metadata()?;
                    entries.insert(
                        item.path(),
                        DirectoryEntry {
                            path: item.path(),
                            metadata: FileMetadata {
                                len: metadata.len(),
                                directory: metadata.is_dir(),
                            },
                        },
                    );
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && self.is_dir(path) => {}
            Err(e) => return Err(e),
        }
        let prefix = format!("{}/", key(path));
        for (name, file) in &self.embedded {
            let Some(relative) = name.strip_prefix(&prefix) else {
                continue;
            };
            let depth = relative.split('/').count();
            let mut child = file.path.clone();
            for _ in 1..depth {
                child.pop();
            }
            // Use the caller's parent spelling for every child. On Windows an
            // EVB installed under a verbatim path and a normal disk directory
            // name the same location; archive grouping compares these parents.
            if let Some(name) = child.file_name() {
                child = path.join(name);
            }
            let directory = depth > 1;
            let normalized = key(&child);
            if directory
                && entries
                    .iter()
                    .any(|(path, entry)| key(path) == normalized && entry.metadata.directory)
            {
                continue;
            }
            entries.retain(|path, _| key(path) != normalized);
            entries.insert(
                child.clone(),
                DirectoryEntry {
                    path: child,
                    metadata: FileMetadata {
                        len: if directory { 0 } else { file.source.len() },
                        directory,
                    },
                },
            );
        }
        Ok(entries.into_values().collect())
    }
    /// Opens a random-access source, preserving lazy transforms for video.
    pub fn source(self: &Arc<Self>, path: &Path) -> io::Result<Arc<dyn ReadAt>> {
        if let Some(file) = self.embedded.get(&key(path)) {
            return Ok(file.source.clone());
        }
        Ok(Arc::new(ArcView::open(path)?.with_files(self.clone())))
    }
    /// Opens a contiguous view for archive and PE parsers. An embedded file's
    /// immutable bytes are retained only after this explicit access.
    pub fn open(self: &Arc<Self>, path: &Path) -> io::Result<ArcView> {
        if let Some(file) = self.embedded.get(&key(path)) {
            let mut cached = file
                .bytes
                .lock()
                .map_err(|_| io::Error::other("Embedded file cache is unavailable"))?;
            let bytes = if let Some(bytes) = &*cached {
                bytes.clone()
            } else {
                let len = usize::try_from(file.source.len()).map_err(io::Error::other)?;
                let bytes: Arc<[u8]> = file.source.read_at(0, len)?.into_owned().into();
                *cached = Some(bytes.clone());
                bytes
            };
            return Ok(ArcView::from_bytes(file.path.clone(), bytes).with_files(self.clone()));
        }
        Ok(ArcView::open(path)?.with_files(self.clone()))
    }
    pub fn read(self: &Arc<Self>, path: &Path) -> io::Result<Vec<u8>> {
        let source = self.source(path)?;
        Ok(source
            .read_at(0, usize::try_from(source.len()).map_err(io::Error::other)?)?
            .into_owned())
    }
    /// Virtual paths retain their installed name; physical paths resolve links.
    pub fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        if let Some(file) = self.embedded.get(&key(path)) {
            return Ok(file.path.clone());
        }
        if self.is_dir(path) && !path.is_dir() {
            return Ok(path.to_path_buf());
        }
        path.canonicalize()
    }
}

#[cfg(test)]
#[path = "../tests/files.rs"]
mod tests;
