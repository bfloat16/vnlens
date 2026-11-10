//! Task status stays beside the path, with details expanding above its tile.

use super::browser_view::glass;
use super::view::{button, spinner, tooltip};
use super::*;
use crate::icons::glyph;

impl Workspace {
    pub(super) fn status_dock(
        &self,
        inset: Pixels,
        window: &Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let busy = self.pending > 0
            || self.name_jobs.iter().any(|job| job.running)
            || self.preview_loading
            || self.image_view.frames.pending_count() > 0
            || self.extracting
            || self.converting
            || self.columns.iter().any(|column| column.loading);
        let failed = self.error.is_some();
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
                                spinner("status-busy", 15., ACCENT).into_any_element()
                            } else if failed {
                                glyph("icons/alert.svg", 16., DANGER).into_any_element()
                            } else {
                                glyph("icons/check.svg", 16., SUCCESS).into_any_element()
                            })
                            .when(busy && failed, |tile| {
                                tile.child(
                                    div()
                                        .absolute()
                                        .top(px(4.))
                                        .right(px(4.))
                                        .size(px(5.))
                                        .rounded_full()
                                        .bg(rgb(DANGER)),
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
        glass()
            .id("status-details")
            .absolute()
            .left_0()
            .bottom(px(38.))
            .w((window.viewport_size().width - px(24.)).min(px(500.)))
            .max_h((window.viewport_size().height - px(92.)).max(px(60.)))
            .overflow_y_scroll()
            .rounded(px(10.))
            .p(px(8.))
            .flex()
            .flex_col()
            .gap(px(6.))
            .font_family(UI_FONT)
            .text_size(px(11.))
            .text_color(rgb(SECONDARY))
            .occlude()
            .when(self.status != "Ready", |view| {
                view.child(status_line(self.status.clone(), SECONDARY))
            })
            .when(!self.imports.is_empty(), |view| {
                view.child(
                    button("cancel-opening", "Cancel opening", false, true).on_click(cx.listener(
                        |this, _, _, cx| {
                            for request in &this.imports {
                                request.store(true, Ordering::Relaxed);
                            }
                            cx.notify();
                        },
                    )),
                )
            })
            .when(self.pending > 0, |view| {
                view.child(status_line(
                    format!("Opening… · {} requests", self.pending),
                    ACCENT,
                ))
            })
            .children(
                self.columns
                    .iter()
                    .filter(|column| column.loading)
                    .map(|column| {
                        status_line(
                            format!("Loading… · {}", column.folder.target.export_name()),
                            ACCENT,
                        )
                    }),
            )
            .when(self.preview_loading, |view| {
                let name = self.selected_item().map_or("", |item| item.name.as_str());
                view.child(status_line(format!("Preparing preview… · {name}"), ACCENT))
            })
            .when(self.image_view.frames.pending_count() > 0, |view| {
                view.child(status_line(
                    format!(
                        "Preparing thumbnails… · {} remaining",
                        self.image_view.frames.pending_count()
                    ),
                    ACCENT,
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
                } else if self.status == "Ready" && self.error.is_none() {
                    view.child(status_line("Ready".into(), SECONDARY))
                } else {
                    view
                }
            })
            .when(self.converting, |view| {
                view.child(status_line("Exporting…".into(), ACCENT))
            })
            .children(self.name_jobs.iter().map(|job| {
                status_line(
                    format!(
                        "{} · {} / {} · {} names · {} failed",
                        job.label(),
                        job.progress.completed,
                        job.progress.total,
                        job.progress.resolved,
                        job.progress.failed
                    ),
                    if job.running { ACCENT } else { SECONDARY },
                )
            }))
            .when(self.name_jobs.iter().any(|job| job.running), |view| {
                view.child(
                    button("cancel-names", "Cancel name recovery", false, true)
                        .on_click(cx.listener(|this, _, _, cx| this.cancel_names(cx))),
                )
            })
            .when(self.extracting, |view| {
                view.child(status_line(
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
                    ACCENT,
                ))
                .child(
                    div()
                        .h(px(4.))
                        .flex_shrink_0()
                        .rounded_full()
                        .bg(rgb(BORDER))
                        .child(div().h_full().rounded_full().bg(rgb(ACCENT)).w(relative(
                            if self.progress.total == 0 {
                                0.
                            } else {
                                self.progress.completed as f32 / self.progress.total as f32
                            },
                        ))),
                )
            })
            .when_some(self.error.as_ref(), |view, error| {
                let copied = error.clone();
                view.child(
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
                        .text_color(rgb(DANGER))
                        .hover(|style| style.bg(rgba(0xffffff0d)))
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .my_auto()
                                .whitespace_normal()
                                .child(error.clone()),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_shrink_0()
                                .items_center()
                                .gap(px(4.))
                                .child(
                                    error_action("copy-error", "icons/copy.svg")
                                        .tooltip(tooltip("Copy"))
                                        .on_click(cx.listener(move |_, _, _, cx| {
                                            cx.write_to_clipboard(ClipboardItem::new_string(
                                                copied.clone(),
                                            ));
                                        })),
                                )
                                .child(
                                    error_action("dismiss-error", "icons/window-close.svg")
                                        .tooltip(tooltip("Dismiss"))
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.error = None;
                                            cx.notify();
                                        })),
                                ),
                        ),
                )
            })
            .when(self.extracting || self.output.is_some(), |view| {
                view.child(self.status_actions(cx))
            })
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
}

fn error_action(id: impl Into<ElementId>, icon: &'static str) -> Stateful<Div> {
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

fn status_line(text: String, color: u32) -> Div {
    div()
        .w_full()
        .flex_shrink_0()
        .whitespace_normal()
        .text_color(rgb(color))
        .child(text)
}
