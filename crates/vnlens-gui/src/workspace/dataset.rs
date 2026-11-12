//! Dataset selection and background scheduling; mapping lives in vnlens-dataset.

use super::*;

impl Workspace {
    pub(super) fn dataset_game(&self) -> Option<Arc<vnlens_engine::Identification>> {
        if self
            .columns
            .get(self.active)
            .is_some_and(|column| column.loading || column.failed)
            || self
                .columns
                .get(self.active + 1)
                .is_some_and(|column| column.loading || column.failed)
        {
            return None;
        }
        let column = if self
            .columns
            .get(self.active + 1)
            .is_some_and(|column| !column.loading && !column.failed)
            && self.columns[self.active]
                .selected
                .is_some_and(|row| self.columns[self.active].folder.items[row].container)
        {
            self.active + 1
        } else {
            self.active
        };
        let target = self
            .columns
            .get(column)
            .filter(|column| !matches!(column.folder.target, Target::Opened))
            .map(|column| &column.folder.target)
            .or_else(|| self.selected_item().map(|item| &item.target))?;
        let game = match target {
            Target::Directory(_, game) | Target::File(_, game) | Target::ArchiveSet(_, game) => {
                game
            }
            Target::ArchiveDirectory { archive, .. } | Target::Entry { archive, .. } => {
                &archive.game
            }
            Target::Opened => return None,
        };
        vnlens_dataset::supports(game.engine).then(|| game.clone())
    }

    pub(super) fn dataset_dialog(&mut self, cx: &mut Context<Self>) {
        if self.extracting || self.converting {
            return;
        }
        let Some(game) = self.dataset_game() else {
            return;
        };
        self.show_export_menu = false;
        self.path_menu = None;
        let paths = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("Choose an empty dataset folder".into()),
        });
        cx.spawn(async move |weak, cx| match paths.await {
            Ok(Ok(Some(paths))) => {
                if let Some(output) = paths.into_iter().next() {
                    let _ = weak.update(cx, |this, cx| {
                        if this.extracting || this.converting {
                            return;
                        }
                        this.extracting = true;
                        this.dataset_progress = Some(vnlens_dataset::Progress::default());
                        this.cancel = Arc::new(AtomicBool::new(false));
                        this.output = Some(output.clone());
                        this.show_status = true;
                        let cancel = this.cancel.clone();
                        let sender = this.sender.clone();
                        cx.background_executor()
                            .spawn(async move {
                                let mut last_update = Instant::now();
                                let mut stage = vnlens_dataset::Stage::Indexing;
                                let result = vnlens_dataset::generate(
                                    game,
                                    &output,
                                    cancel,
                                    |progress, error| {
                                        if error.is_some()
                                            || stage != progress.stage
                                            || progress.completed == progress.total
                                            || last_update.elapsed() >= Duration::from_millis(80)
                                        {
                                            stage = progress.stage;
                                            let _ = sender
                                                .send(Event::DatasetProgress(progress, error));
                                            last_update = Instant::now();
                                        }
                                    },
                                );
                                let _ = sender.send(Event::DatasetFinished(result));
                            })
                            .detach();
                        cx.notify();
                    });
                }
            }
            Ok(Ok(None)) => {}
            result => {
                let _ = weak.update(cx, |this, cx| {
                    this.error(format!("Cannot choose dataset folder: {result:?}"));
                    cx.notify();
                });
            }
        })
        .detach();
    }
}
