//! Game-level name recovery and immutable browser snapshots. Scanning owns
//! separate archive readers. Timed reports never hold the preview/export lock.
use super::*;
use crate::archive::MountedArchive;
use nvlens_archive::krkr::{NameProgress, NameRecovery};
use std::collections::BTreeMap;

pub(super) struct Job {
    root: PathBuf,
    request: Arc<AtomicBool>,
    paths: Arc<BTreeMap<PathBuf, Vec<String>>>,
    pub progress: NameProgress,
    pub running: bool,
}
impl Drop for Job {
    fn drop(&mut self) {
        self.request.store(true, Ordering::Relaxed);
    }
}
impl Job {
    pub(super) fn label(&self) -> &'static str {
        if self.request.load(Ordering::Relaxed) {
            "Name recovery cancelled"
        } else if self.running {
            "Recovering names"
        } else {
            "Name recovery finished"
        }
    }
}
pub(super) struct Update {
    pub root: PathBuf,
    pub request: Arc<AtomicBool>,
    pub paths: Arc<BTreeMap<PathBuf, Vec<String>>>,
    pub progress: NameProgress,
    pub errors: Vec<String>,
    pub finished: bool,
}
pub(super) struct Refresh {
    pub id: u64,
    pub previous: Arc<MountedArchive>,
    pub folder: Folder,
    pub remapped: Vec<usize>,
}
fn archive(target: &Target) -> Option<&Arc<MountedArchive>> {
    match target {
        Target::ArchiveDirectory { archive, .. } | Target::Entry { archive, .. } => Some(archive),
        _ => None,
    }
}
fn prepare(
    columns: Vec<(u64, Arc<MountedArchive>, usize, Vec<String>)>,
) -> anyhow::Result<Vec<Refresh>> {
    let mut replacements: Vec<(Arc<MountedArchive>, Arc<MountedArchive>, Vec<usize>)> = Vec::new();
    let mut output = Vec::new();
    for (id, old, directory, paths) in columns {
        let position = if let Some(i) = replacements
            .iter()
            .position(|(before, _, _)| Arc::ptr_eq(before, &old))
        {
            i
        } else {
            let newer = Arc::new(old.with_paths(paths)?);
            let remapped = (0..old.directories.len())
                .map(|d| old.renamed_directory(d, &newer))
                .collect();
            replacements.push((old.clone(), newer, remapped));
            replacements.len() - 1
        };
        let (_, newer, remapped) = &replacements[position];
        output.push(Refresh {
            id,
            previous: old,
            folder: Folder::archive(newer.clone(), remapped[directory]),
            remapped: remapped.clone(),
        });
    }
    Ok(output)
}
fn mapped(target: &Target, update: &Refresh) -> Target {
    let Some(newer) = archive(&update.folder.target) else {
        return target.clone();
    };
    match target {
        Target::Entry { archive, index } if Arc::ptr_eq(archive, &update.previous) => {
            Target::Entry {
                archive: newer.clone(),
                index: *index,
            }
        }
        Target::ArchiveDirectory { archive, directory }
            if Arc::ptr_eq(archive, &update.previous) =>
        {
            Target::ArchiveDirectory {
                archive: newer.clone(),
                directory: update.remapped[*directory],
            }
        }
        _ => target.clone(),
    }
}
fn selected_row(folder: &Folder, target: Target) -> Option<usize> {
    let target = match (&folder.target, target) {
        (
            Target::ArchiveDirectory {
                archive: parent,
                directory: parent_id,
            },
            Target::ArchiveDirectory { archive, directory },
        ) if Arc::ptr_eq(parent, &archive) => {
            let mut id = directory;
            while let Some(next) = archive.directories[id].parent {
                if next == *parent_id {
                    break;
                }
                id = next;
            }
            Target::ArchiveDirectory {
                archive,
                directory: id,
            }
        }
        (_, target) => target,
    };
    folder
        .items
        .iter()
        .position(|item| item.target.same(&target))
}
impl Workspace {
    pub(super) fn start_names(
        &mut self,
        game: Arc<nvlens_engine::Identification>,
        cx: &mut Context<Self>,
    ) {
        if game.engine != nvlens_engine::Engine::KrkrzHxv4
            || self.name_jobs.iter().any(|j| j.root == game.root)
        {
            return;
        }
        let request = Arc::new(AtomicBool::new(false));
        self.name_jobs.push(Job {
            root: game.root.clone(),
            request: request.clone(),
            paths: Arc::new(BTreeMap::new()),
            progress: Default::default(),
            running: true,
        });
        let sender = self.sender.clone();
        cx.background_executor()
            .spawn(async move {
                let mut latest = Arc::new(BTreeMap::new());
                let mut progress = NameProgress::default();
                let result = (|| -> anyhow::Result<()> {
                    let mut inputs = Vec::new();
                    for entry in game.files.read_dir(&game.root)? {
                        if request.load(Ordering::Relaxed) {
                            return Err(nvlens_core::Error::Cancelled.into());
                        }
                        let path = entry.path;
                        if !entry.metadata.directory
                            && let nvlens_core::ResourceRoute::Archive(route) = game.resource_route(
                                &path.to_string_lossy(),
                                nvlens_core::ResourceOrigin::File,
                                &[],
                            )
                            && route.tag == "xp3/krkr"
                        {
                            inputs.push((path, route.options));
                        }
                    }
                    inputs.sort_by(|a, b| a.0.cmp(&b.0));
                    let mut recovery = NameRecovery::open_in(&inputs, &game.files, &request)?;
                    let mut reported_revision = None;
                    let mut last = Instant::now();
                    loop {
                        let more = recovery.step(&request)?;
                        if !more || last.elapsed() >= Duration::from_secs(2) {
                            if reported_revision != Some(recovery.revision()) {
                                latest = Arc::new(recovery.paths());
                                reported_revision = Some(recovery.revision());
                            }
                            progress = recovery.progress();
                            let _ = sender.send(Event::Names(Update {
                                root: game.root.clone(),
                                request: request.clone(),
                                paths: latest.clone(),
                                progress,
                                errors: recovery.take_errors(),
                                finished: !more,
                            }));
                            last = Instant::now();
                        }
                        if !more {
                            break;
                        }
                    }
                    Ok(())
                })();
                if let Err(error) = result {
                    let errors = if request.load(Ordering::Relaxed) {
                        Vec::new()
                    } else {
                        vec![format!("Name recovery: {error:#}")]
                    };
                    let _ = sender.send(Event::Names(Update {
                        root: game.root.clone(),
                        request,
                        paths: latest,
                        progress,
                        errors,
                        finished: true,
                    }));
                }
            })
            .detach();
    }
    pub(super) fn receive_names(&mut self, update: Update, cx: &mut Context<Self>) {
        let Some(job) = self
            .name_jobs
            .iter_mut()
            .find(|j| j.root == update.root && Arc::ptr_eq(&j.request, &update.request))
        else {
            return;
        };
        job.paths = update.paths;
        job.progress = update.progress;
        job.running = !update.finished;
        if let Some(error) = update.errors.into_iter().last() {
            self.error = Some(error);
        }
        self.refresh_names(cx);
    }
    pub(super) fn refresh_names(&mut self, cx: &mut Context<Self>) {
        if self.names_refreshing {
            return;
        }
        let mut columns = Vec::new();
        for column in &self.columns {
            if column.loading {
                continue;
            }
            if let Target::ArchiveDirectory { archive, directory } = &column.folder.target
                && let Some(job) = self.name_jobs.iter().find(|j| j.root == archive.game.root)
                && let Some(paths) = job.paths.get(&archive.source_path)
                && paths != &archive.paths
            {
                columns.push((column.id, archive.clone(), *directory, paths.clone()));
            }
        }
        if columns.is_empty() {
            return;
        }
        self.names_refreshing = true;
        let sender = self.sender.clone();
        cx.background_executor()
            .spawn(async move {
                let _ = sender.send(Event::NamesRefreshed(prepare(columns)));
            })
            .detach();
    }
    pub(super) fn receive_name_refresh(
        &mut self,
        result: anyhow::Result<Vec<Refresh>>,
        cx: &mut Context<Self>,
    ) {
        self.names_refreshing = false;
        let updates = match result {
            Ok(v) => v,
            Err(error) => {
                self.error(format!("Refreshing recovered names: {error:#}"));
                return;
            }
        };
        apply_updates(
            &mut self.columns,
            &mut self.selection,
            &mut self.active,
            updates,
        );
        self.path_menu = None;
        // A folder opened while this snapshot was being prepared is updated by
        // a subsequent background pass, never by rebuilding its list here.
        self.refresh_names(cx);
    }
    pub(super) fn cancel_names(&mut self, cx: &mut Context<Self>) {
        for job in &self.name_jobs {
            if job.running {
                job.request.store(true, Ordering::Relaxed);
            }
        }
        cx.notify();
    }
}

fn apply_updates(
    columns: &mut Vec<Column>,
    selection: &mut Option<(usize, usize)>,
    active: &mut usize,
    updates: Vec<Refresh>,
) {
    for update in updates {
        let Some(depth) = columns.iter().position(|c| {
            c.id == update.id
                && !c.loading
                && archive(&c.folder.target).is_some_and(|a| Arc::ptr_eq(a, &update.previous))
        }) else {
            continue;
        };
        let column = &mut columns[depth];
        let selected = column
            .selected
            .and_then(|row| column.folder.items.get(row))
            .map(|item| mapped(&item.target, &update));
        let row = selected.and_then(|target| selected_row(&update.folder, target));
        column.folder = update.folder;
        column.selected = row;
        if selection.is_some_and(|(d, _)| d == depth) {
            *selection = row.map(|r| (depth, r));
        }
    }

    // Resolving the root hash removes its synthetic directory. Keep the deeper
    // column (and its current entry selection) instead of displaying it twice.
    let mut depth = 1;
    while depth + 1 < columns.len() {
        if columns[depth]
            .folder
            .target
            .same(&columns[depth + 1].folder.target)
        {
            columns.remove(depth);
            if *active > depth {
                *active -= 1;
            }
            if let Some((selected_depth, _)) = selection.as_mut()
                && *selected_depth > depth
            {
                *selected_depth -= 1;
            }
        } else {
            depth += 1;
        }
    }
}
