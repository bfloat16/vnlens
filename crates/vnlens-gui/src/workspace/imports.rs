//! Independent imports publish each result immediately. Finished jobs remain in
//! their batch only until its last result, so aggregate progress retains them.

use super::*;

pub(super) struct Job {
    pub path: PathBuf,
    pub request: Arc<AtomicBool>,
    pub finished: bool,
}

pub(super) struct Batch {
    pub jobs: Vec<Job>,
}

impl Workspace {
    pub(super) fn open_paths(&mut self, paths: Vec<PathBuf>, cx: &mut Context<Self>) {
        if paths.is_empty() {
            return;
        }
        let jobs: Vec<_> = paths
            .into_iter()
            .map(|path| Job {
                path,
                request: Arc::new(AtomicBool::new(false)),
                finished: false,
            })
            .collect();
        for job in &jobs {
            let path = job.path.clone();
            let request = job.request.clone();
            let sender = self.sender.clone();
            cx.background_executor()
                .spawn(async move {
                    let result = Item::from_path_cancellable(path, &request, &|_, _| {});
                    let _ = sender.send(Event::Imported(request, result));
                })
                .detach();
        }
        self.imports.push(Batch { jobs });
        cx.notify();
    }

    pub(super) fn receive_import(
        &mut self,
        request: Arc<AtomicBool>,
        result: anyhow::Result<Item>,
        cx: &mut Context<Self>,
    ) {
        let Some(job) = self
            .imports
            .iter_mut()
            .flat_map(|batch| &mut batch.jobs)
            .find(|job| !job.finished && Arc::ptr_eq(&job.request, &request))
        else {
            return;
        };
        job.finished = true;
        let path = job.path.clone();
        self.imports
            .retain(|batch| batch.jobs.iter().any(|job| !job.finished));
        if request.load(Ordering::Relaxed) {
            return;
        }
        match result {
            Ok(mut item) => {
                item.set_compose_pimg(self.preferences.compose_pimg());
                if let Target::File(_, game)
                | Target::Directory(_, game)
                | Target::ArchiveSet(_, game) = &item.target
                {
                    self.start_names(game.clone(), cx);
                }
                let root = &mut self.columns[0];
                if !root
                    .folder
                    .items
                    .iter()
                    .any(|old| old.target.same(&item.target))
                {
                    root.selected = None;
                }
                let row = root.folder.insert(item);
                self.select(0, row, cx);
            }
            Err(error) => self.error(format!("Opening {}: {error:#}", path.display())),
        }
    }
}
