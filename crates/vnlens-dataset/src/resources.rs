//! Index-only collection within one game instance. Payloads are opened on demand;
//! Verified engine patch priority selects overrides; equal-priority duplicate
//! logical names remain ambiguous. Requested companions cache decoded bytes.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use vnlens_core::{
    Catalog, Error, Opened, ResourceOrigin, ResourceResolver, ResourceRoute, Result,
};
use vnlens_engine::Identification;

use crate::Progress;

#[derive(Debug)]
enum Source {
    File(PathBuf),
    Entry { archive: usize, index: usize },
}

pub(crate) struct Resource {
    pub name: String,
    pub route: ResourceRoute,
    source: Source,
    companion: OnceLock<Vec<u8>>,
    priority: u8,
}

impl std::fmt::Debug for Resource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Resource")
            .field("name", &self.name)
            .field("route", &self.route)
            .field("source", &self.source)
            .field("priority", &self.priority)
            .field("companion_cached", &self.companion.get().is_some())
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct Resources {
    game: Arc<Identification>,
    archives: Vec<Opened>,
    pub items: Vec<Resource>,
    names: BTreeMap<String, (u8, Option<usize>)>,
    cancel: Arc<AtomicBool>,
}

pub(crate) fn normalized(name: &str) -> String {
    name.replace('\\', "/").to_ascii_lowercase()
}

pub(crate) fn check(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

impl Resources {
    pub fn collect(
        game: Arc<Identification>,
        output: &Path,
        cancel: Arc<AtomicBool>,
        progress: &mut Progress,
        report: &mut impl FnMut(Progress, Option<String>),
    ) -> Result<Self> {
        let mut resources = Self {
            game,
            archives: Vec::new(),
            items: Vec::new(),
            names: BTreeMap::new(),
            cancel,
        };
        let mut pending = vec![resources.game.root.clone()];
        let mut visited = HashSet::new();
        let catalog = Catalog::load();
        while let Some(directory) = pending.pop() {
            check(&resources.cancel)?;
            let directory = resources.game.files.canonicalize(&directory)?;
            if directory == output || !visited.insert(directory.clone()) {
                continue;
            }
            // An embedded updater is another instance, even when its engine matches.
            let context = match resources.game.for_directory(&directory, &resources.cancel) {
                Ok(context) => context,
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(error) => {
                    progress.failed += 1;
                    report(*progress, Some(format!("{}: {error}", directory.display())));
                    continue;
                }
            };
            if context.root != resources.game.root {
                continue;
            }
            let mut entries = resources.game.files.read_dir(&directory)?;
            entries.sort_by(|a, b| a.path.cmp(&b.path));
            progress.total += entries.len();
            for entry in entries {
                check(&resources.cancel)?;
                if entry.metadata.directory {
                    pending.push(entry.path);
                } else if let Err(error) = resources.add_file(&entry.path, &catalog) {
                    check(&resources.cancel)?;
                    progress.failed += 1;
                    report(
                        *progress,
                        Some(format!("{}: {error}", entry.path.display())),
                    );
                }
                progress.completed += 1;
                report(*progress, None);
            }
        }
        for (index, item) in resources.items.iter().enumerate() {
            check(&resources.cancel)?;
            resources
                .names
                .entry(normalized(&item.name))
                .and_modify(|(priority, selected)| {
                    if item.priority > *priority {
                        *priority = item.priority;
                        *selected = Some(index);
                    } else if item.priority == *priority {
                        *selected = None;
                    }
                })
                .or_insert((item.priority, Some(index)));
        }
        Ok(resources)
    }

    fn add_file(&mut self, path: &Path, catalog: &Catalog) -> Result<()> {
        let name = path
            .strip_prefix(&self.game.root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let route = self.game.resource_route(&name, ResourceOrigin::File, &[]);
        if matches!(route, ResourceRoute::Archive(_)) {
            let ResourceRoute::Archive(route) = self.game.route_path(path)? else {
                return Ok(());
            };
            let opened = catalog.open_view(Arc::new(self.game.files.open(path)?), &route)?;
            let archive = self.archives.len();
            for (index, entry) in opened.archive.entries().iter().enumerate() {
                check(&self.cancel)?;
                let route =
                    self.game
                        .resource_route(&entry.name, ResourceOrigin::Entry(entry.kind), &[]);
                if matches!(
                    route,
                    ResourceRoute::Script(_)
                        | ResourceRoute::Audio(_)
                        | ResourceRoute::Media { .. }
                ) {
                    self.items.push(Resource {
                        name: entry.name.clone(),
                        route,
                        source: Source::Entry { archive, index },
                        companion: OnceLock::new(),
                        priority: crate::yuris::archive_priority(&name),
                    });
                }
            }
            self.archives.push(opened);
        } else if matches!(
            route,
            ResourceRoute::Script(_) | ResourceRoute::Audio(_) | ResourceRoute::Media { .. }
        ) {
            self.items.push(Resource {
                name,
                route,
                source: Source::File(path.to_owned()),
                companion: OnceLock::new(),
                priority: 0,
            });
        }
        Ok(())
    }

    pub fn find(&self, name: &str) -> Option<usize> {
        self.names.get(&normalized(name)).and_then(|(_, id)| *id)
    }

    pub fn read(&self, index: usize) -> Result<Vec<u8>> {
        check(&self.cancel)?;
        let item = &self.items[index];
        match &item.source {
            Source::File(path) => {
                let bytes = self.game.files.read(path)?;
                if let ResourceRoute::Script(tag) = item.route {
                    Ok(vnlens_script::decode_with_resources_as(
                        tag,
                        &bytes,
                        Some(self),
                        self.game.resource_options(),
                        &self.cancel,
                    )?
                    .into_owned())
                } else {
                    Ok(bytes)
                }
            }
            Source::Entry { archive, index } => {
                let archive = &self.archives[*archive].archive;
                Ok(archive.open_entry(&archive.entries()[*index])?.into_owned())
            }
        }
    }

    pub fn write(&self, index: usize, output: &Path, name: &str) -> Result<PathBuf> {
        check(&self.cancel)?;
        // A multiplexed container is only a voice when the selected audio
        // reader finds an audio stream. Keep its original bytes after validation.
        if let ResourceRoute::Media { audio, .. } = self.items[index].route {
            let bytes = self.read(index)?;
            if vnlens_audio::metadata_as(audio, &bytes)?.is_none() {
                return Err(Error::Unsupported(
                    "Voice container has no audio stream".into(),
                ));
            }
            check(&self.cancel)?;
            let path = vnlens_io::filesystem::write_under(output, name, &bytes)?;
            check(&self.cancel)?;
            return Ok(path);
        }
        let source = match &self.items[index].source {
            Source::File(path) => Some(self.game.files.source(path)?),
            Source::Entry { archive, index } => {
                let archive = &self.archives[*archive].archive;
                archive.open_entry_source(&archive.entries()[*index])?
            }
        };
        let (logical_name, origin) = match &self.items[index].source {
            Source::File(_) => (self.items[index].name.as_str(), ResourceOrigin::File),
            Source::Entry { archive, index } => {
                let entry = &self.archives[*archive].archive.entries()[*index];
                (entry.name.as_str(), ResourceOrigin::Entry(entry.kind))
            }
        };
        let validate = |bytes: &[u8]| -> Result<()> {
            if bytes.is_empty() {
                return Err(Error::Corrupt {
                    offset: 0,
                    reason: "Voice resource is empty".into(),
                });
            }
            if !matches!(
                self.game.resource_route(logical_name, origin, bytes),
                ResourceRoute::Audio(_) | ResourceRoute::Media { .. }
            ) {
                return Err(Error::Unsupported(
                    "Voice reference does not route to audio".into(),
                ));
            }
            Ok(())
        };
        let result = if let Some(source) = source {
            validate(&source.read_at(0, source.len().min(64) as usize)?)?;
            vnlens_io::filesystem::write_under_with(output, name, |file| {
                let mut reader = source.reader(self.cancel.clone())?;
                std::io::copy(&mut reader, file)?;
                Ok(())
            })
        } else {
            let bytes = self.read(index)?;
            validate(&bytes)?;
            check(&self.cancel)?;
            vnlens_io::filesystem::write_under(output, name, &bytes)
        };
        check(&self.cancel)?;
        Ok(result?)
    }
}

impl ResourceResolver for Resources {
    fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
        check(&self.cancel)?;
        let Some(index) = self.find(name) else {
            if self.names.contains_key(&normalized(name)) {
                return Err(Error::Unsupported(format!(
                    "Ambiguous dataset resource: {name}"
                )));
            }
            return Ok(None);
        };
        let cache = &self.items[index].companion;
        if let Some(bytes) = cache.get() {
            return Ok(Some(bytes.clone()));
        }
        let bytes = self.read(index)?;
        let _ = cache.set(bytes.clone());
        Ok(Some(bytes))
    }
}

#[cfg(test)]
#[path = "../tests/resources.rs"]
mod tests;
