//! Task status stays beside the path, with details expanding above its tile.

use super::browser_view::glass;
use super::view::{button, spinner, tooltip};
use super::*;
use crate::icons::glyph;

impl Workspace {
    fn routing_warning(&self) -> Option<&'static str> {
        self.columns
            .iter()
            .rev()
            .find(|column| {
                !column.loading && !column.failed && !matches!(column.folder.target, Target::Opened)
            })
            .map(|column| &column.folder.target)
            .or_else(|| self.selected_item().map(|item| &item.target))
            .and_then(Target::warning)
    }

    pub(super) fn status_dock(
        &self,
        inset: Pixels,
        window: &Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let busy = !self.imports.is_empty()
            || self.name_jobs.iter().any(|job| job.running)
            || self.preview_loading
            || self.image_view.frames.pending_count() > 0
            || self.extracting
            || self.converting
            || self.columns.iter().any(|column| column.loading);
        let failed = !self.errors.is_empty();
        let warning = self.routing_warning();
        let progress = self.activity_progress();
        div()
            .absolute()
            .left(px(12.))
            .right(px(12.))
            .bottom(px(12.))
            .flex()
            .items_end()
            .gap(px(8.))
            .child(
                div()
                    .relative()
                    .flex_shrink_0()
                    .child(
                        glass()
                            .id("status-tile")
                            .size(px(30.))
                            .rounded(px(10.))
                            .relative()
                            .flex()
                            .items_center()
                            .justify_center()
                            .cursor_pointer()
                            .occlude()
                            .hover(|style| style.bg(rgb(CONTROL)))
                            .tooltip(tooltip("Activity"))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.show_status = !this.show_status;
                                cx.notify();
                            }))
                            .child(if busy {
                                if let Some(progress) = progress {
                                    progress_ring(15., progress).into_any_element()
                                } else {
                                    spinner("status-busy", 15., ACCENT).into_any_element()
                                }
                            } else if failed {
                                glyph("icons/alert.svg", 16., DANGER).into_any_element()
                            } else if warning.is_some() {
                                glyph("icons/alert.svg", 16., WARNING).into_any_element()
                            } else {
                                glyph("icons/check.svg", 16., SUCCESS).into_any_element()
                            })
                            .when(busy && (failed || warning.is_some()), |tile| {
                                tile.child(
                                    div()
                                        .absolute()
                                        .top(px(4.))
                                        .right(px(4.))
                                        .size(px(5.))
                                        .rounded_full()
                                        .bg(rgb(if failed { DANGER } else { WARNING })),
                                )
                            }),
                    )
                    .when(self.show_status, |view| {
                        view.child(self.status_details(window, cx))
                    }),
            )
            .when(
                !self.show_settings && !self.columns[0].folder.items.is_empty(),
                |view| view.child(self.path_bar(window, cx)),
            )
            .child(div().flex_1().min_w_0())
            .when(inset > px(0.) && self.selection.is_some(), |view| {
                view.child(
                    button(
                        "export-preview",
                        "Export…",
                        true,
                        !self.extracting
                            && !self.converting
                            && !self.preview_loading
                            && !self.preview_failed
                            && self.preview.is_some(),
                    )
                    .occlude()
                    .on_click(cx.listener(|this, _, _, cx| this.export_preview(cx))),
                )
            })
    }

    fn status_details(&self, window: &Window, cx: &mut Context<Self>) -> impl IntoElement {
        let content = div()
            .id("status-content")
            .max_h((window.viewport_size().height - px(108.)).max(px(44.)))
            .w_full()
            .overflow_y_scroll()
            .track_scroll(&self.status_scroll)
            .pr(px(8.))
            .flex()
            .flex_col()
            .gap(px(6.))
            .when_some(self.routing_warning(), |view, warning| {
                view.child(status_line(warning.into(), WARNING))
            })
            .font_family(UI_FONT)
            .text_size(px(11.))
            .text_color(rgb(SECONDARY))
            .occlude()
            .when(self.status != "Ready", |view| {
                view.child(status_line(self.status.clone(), SECONDARY))
            })
            .children(self.imports.iter().enumerate().map(|(index, batch)| {
                let requests: Vec<_> = batch
                    .jobs
                    .iter()
                    .filter(|job| !job.finished)
                    .map(|job| job.request.clone())
                    .collect();
                let cancelled = requests
                    .iter()
                    .all(|request| request.load(Ordering::Relaxed));
                let completed = batch.jobs.iter().filter(|job| job.finished).count();
                let total = batch.jobs.len();
                let progress = fraction(completed as u64, total as u64);
                progress_line(
                    ("import-progress", index),
                    format!(
                        "{} · {} / {} · {:.1}%",
                        if cancelled {
                            "Cancelling opening…"
                        } else {
                            "Opening…"
                        },
                        completed,
                        total,
                        progress * 100.,
                    ),
                    Some(progress),
                )
                .child(
                    status_action(("cancel-opening", index), "icons/window-close.svg")
                        .tooltip(tooltip("Cancel opening"))
                        .on_click(cx.listener(move |_, _, _, cx| {
                            for request in &requests {
                                request.store(true, Ordering::Relaxed);
                            }
                            cx.notify();
                        })),
                )
            }))
            .children(
                self.columns
                    .iter()
                    .filter(|column| column.loading)
                    .map(|column| {
                        progress_line(
                            ("folder-progress", column.id),
                            format!("Loading… · {}", column.folder.target.export_name()),
                            None,
                        )
                    }),
            )
            .when(self.preview_loading, |view| {
                let name = self.selected_item().map_or("", |item| item.name.as_str());
                view.child(progress_line(
                    "preview-progress",
                    format!("Preparing preview… · {name}"),
                    None,
                ))
            })
            .when(self.image_view.frames.pending_count() > 0, |view| {
                view.child(progress_line(
                    "thumbnails-progress",
                    format!(
                        "Preparing thumbnails… · {} remaining",
                        self.image_view.frames.pending_count()
                    ),
                    None,
                ))
            })
            .when(!self.preview_loading, |view| {
                if let Some(item) = self
                    .selected_item()
                    .filter(|_| !self.preview_failed && self.preview.is_some())
                {
                    view.child(status_line(
                        if self
                            .preview
                            .as_ref()
                            .and_then(|preview| preview.audio.as_ref())
                            .is_some_and(|audio| audio.duration() == 0.)
                        {
                            format!("Empty audio · {}", item.name)
                        } else {
                            format!("Preview ready · {}", item.name)
                        },
                        SECONDARY,
                    ))
                } else if let Some(column) = self
                    .columns
                    .last()
                    .filter(|column| !column.loading && !column.failed)
                {
                    view.child(status_line(
                        format!("{} items", column.folder.items.len()),
                        SECONDARY,
                    ))
                } else if self.status == "Ready" && self.errors.is_empty() {
                    view.child(status_line("Ready".into(), SECONDARY))
                } else {
                    view
                }
            })
            .when(self.converting, |view| {
                view.child(progress_line(
                    "conversion-progress",
                    "Exporting…".into(),
                    None,
                ))
            })
            .children(
                self.name_jobs
                    .iter()
                    .enumerate()
                    .filter(|(_, job)| job.running)
                    .map(|(index, job)| {
                        progress_line(
                            ("names-progress", index),
                            format!(
                                "{} · {} / {} · {} names · {} failed",
                                job.label(),
                                job.progress.completed,
                                job.progress.total,
                                job.progress.resolved,
                                job.progress.failed
                            ),
                            Some(fraction(
                                job.progress.completed as u64,
                                job.progress.total as u64,
                            )),
                        )
                    }),
            )
            .when(self.name_jobs.iter().any(|job| job.running), |view| {
                view.child(
                    button("cancel-names", "Cancel name recovery", false, true)
                        .on_click(cx.listener(|this, _, _, cx| this.cancel_names(cx))),
                )
            })
            .when_some(self.dataset_progress, |view, progress| {
                view.child(progress_line(
                    "dataset-progress",
                    format!(
                        "{} · {} / {} · {} records · {} skipped · {} failed",
                        if self.cancel.load(Ordering::Relaxed) {
                            "Cancelling dataset…"
                        } else {
                            match progress.stage {
                                vnlens_dataset::Stage::Indexing => "Indexing dataset resources",
                                vnlens_dataset::Stage::ReadingScripts => "Reading dataset scripts",
                                vnlens_dataset::Stage::Writing => "Writing dataset",
                            }
                        },
                        progress.completed,
                        progress.total,
                        progress.records,
                        progress.skipped,
                        progress.failed
                    ),
                    Some(fraction(progress.completed as u64, progress.total as u64)),
                ))
            })
            .when(self.extracting && self.dataset_progress.is_none(), |view| {
                view.child(progress_line(
                    "extraction-progress",
                    format!(
                        "{} {} / {} · {} failed",
                        if self.cancel.load(Ordering::Relaxed) {
                            "Cancelling…"
                        } else {
                            "Extracting"
                        },
                        self.progress.completed,
                        self.progress.total,
                        self.progress.failed
                    ),
                    Some(fraction(
                        self.progress.completed as u64,
                        self.progress.total as u64,
                    )),
                ))
            })
            .children(self.errors.iter().enumerate().map(|(index, error)| {
                let copied = error.clone();
                let dismissed = error.clone();
                status_row(error.clone(), DANGER).child(
                    div()
                        .flex()
                        .flex_shrink_0()
                        .items_center()
                        .gap(px(4.))
                        .child(
                            status_action(("copy-error", index), "icons/copy.svg")
                                .tooltip(tooltip("Copy"))
                                .on_click(cx.listener(move |_, _, _, cx| {
                                    cx.write_to_clipboard(ClipboardItem::new_string(
                                        copied.clone(),
                                    ));
                                })),
                        )
                        .child(
                            status_action(("dismiss-error", index), "icons/window-close.svg")
                                .tooltip(tooltip("Dismiss"))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    if let Some(index) =
                                        this.errors.iter().position(|error| error == &dismissed)
                                    {
                                        this.errors.remove(index);
                                    }
                                    cx.notify();
                                })),
                        ),
                )
            }))
            .when(self.extracting || self.output.is_some(), |view| {
                view.child(self.status_actions(cx))
            });
        glass()
            .id("status-details")
            .absolute()
            .left_0()
            .bottom(px(38.))
            .w((window.viewport_size().width - px(24.)).min(px(650.)))
            .rounded(px(10.))
            .p(px(8.))
            .occlude()
            .child(content)
            .child(
                self.status_scrollbar
                    .render(self.status_scroll.clone(), true, Axis::Vertical)
                    .right(px(2.))
                    .top(px(8.))
                    .bottom(px(8.))
                    .w(px(8.)),
            )
    }

    fn status_actions(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_shrink_0()
            .flex_wrap()
            .items_center()
            .gap(px(6.))
            .when(self.extracting, |view| {
                view.child(
                    button(
                        "cancel-export",
                        "Cancel",
                        false,
                        !self.cancel.load(Ordering::Relaxed),
                    )
                    .on_click(cx.listener(|this, _, _, cx| this.cancel_extraction(cx))),
                )
            })
            .when_some(self.output.as_ref(), |view, path| {
                let path = path.clone();
                view.child(
                    button("output", "Show output", false, true)
                        .on_click(move |_, _, cx| cx.open_with_system(&path)),
                )
            })
    }

    fn activity_progress(&self) -> Option<f32> {
        let imports = self
            .imports
            .iter()
            .flat_map(|batch| &batch.jobs)
            .map(|job| if job.finished { 1. } else { 0. });
        let names = self
            .name_jobs
            .iter()
            .filter(|job| job.running && self.imports.is_empty())
            .map(|job| fraction(job.progress.completed as u64, job.progress.total as u64));
        let extraction = (self.extracting && self.imports.is_empty()).then(|| {
            if let Some(progress) = self.dataset_progress {
                fraction(progress.completed as u64, progress.total as u64)
            } else {
                fraction(self.progress.completed as u64, self.progress.total as u64)
            }
        });
        let (sum, count) = imports
            .chain(names)
            .chain(extraction)
            .fold((0., 0_usize), |(sum, count), progress| {
                (sum + f64::from(progress), count + 1)
            });
        (count > 0).then(|| (sum / count as f64) as f32)
    }
}

fn status_action(id: impl Into<ElementId>, icon: &'static str) -> Stateful<Div> {
    div()
        .id(id)
        .size(px(22.))
        .flex_shrink_0()
        .rounded(px(5.))
        .flex()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .hover(|style| style.bg(rgba(0xffffff1a)))
        .child(glyph(icon, 12., SECONDARY))
}

fn status_row(text: String, color: u32) -> Div {
    div()
        .w_full()
        .flex_shrink_0()
        .pl_2()
        .pr_1()
        .py_1()
        .flex()
        .items_end()
        .gap(px(4.))
        .rounded(px(6.))
        .text_color(rgb(color))
        .hover(|style| style.bg(rgba(0xffffff0d)))
        .child(
            div()
                .flex_1()
                .min_w_0()
                .my_auto()
                .whitespace_normal()
                .child(text),
        )
}

fn progress_line(id: impl Into<ElementId>, text: String, progress: Option<f32>) -> Div {
    status_row(text, ACCENT).child(
        div()
            .size(px(22.))
            .flex_shrink_0()
            .flex()
            .items_center()
            .justify_center()
            .child(if let Some(progress) = progress {
                progress_ring(14., progress).into_any_element()
            } else {
                spinner(id, 14., ACCENT).into_any_element()
            }),
    )
}

fn fraction(done: u64, total: u64) -> f32 {
    if total == 0 {
        0.
    } else {
        (done as f64 / total as f64).clamp(0., 1.) as f32
    }
}

fn progress_ring(diameter: f32, progress: f32) -> impl IntoElement {
    canvas(
        |_, _, _| (),
        move |bounds, _, window, _| {
            let center = bounds.center();
            let radius = px(diameter / 2. - 1.);
            for (amount, color) in [(1., BORDER), (progress, ACCENT)] {
                if amount <= 0. {
                    continue;
                }
                let mut path = PathBuilder::stroke(px(1.6));
                path.move_to(point(center.x, center.y - radius));
                // Split at the half circle: SVG arcs with equal start/end
                // points draw nothing, including a completed progress ring.
                let first = amount.min(0.5);
                for end in [first, amount]
                    .into_iter()
                    .take(if amount > 0.5 { 2 } else { 1 })
                {
                    let angle = end * std::f32::consts::TAU;
                    path.arc_to(
                        point(radius, radius),
                        px(0.),
                        false,
                        true,
                        point(
                            center.x + radius * angle.sin(),
                            center.y - radius * angle.cos(),
                        ),
                    );
                }
                match path.build() {
                    Ok(path) => window.paint_path(path, rgb(color)),
                    Err(error) => tracing::error!(%error, "Cannot paint activity progress"),
                }
            }
        },
    )
    .size(px(diameter))
}

fn status_line(text: String, color: u32) -> Div {
    div()
        .w_full()
        .flex_shrink_0()
        .whitespace_normal()
        .text_color(rgb(color))
        .child(text)
}
