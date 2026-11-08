//! Task status stays beside the path, with details expanding above its tile.

use super::browser_view::glass;
use super::view::button;
use super::*;

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
            || self.extracting
            || self.converting
            || self.columns.iter().any(|column| column.loading);
        let failed = !self.errors.is_empty()
            || self.preview_error.is_some()
            || self.columns.iter().any(|column| column.error.is_some());
        let color = if busy {
            ACCENT
        } else if failed {
            0xff8a82
        } else {
            0x30d158
        };
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
                            .text_size(px(14.))
                            .text_color(rgb(color))
                            .cursor_pointer()
                            .occlude()
                            .hover(|style| style.bg(rgb(0x363639)))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.show_status = !this.show_status;
                                cx.notify();
                            }))
                            .child(
                                div()
                                    .child(if busy {
                                        "•••"
                                    } else if failed {
                                        "!"
                                    } else {
                                        "✓"
                                    })
                                    .map(|icon| {
                                        if !busy {
                                            return icon.into_any_element();
                                        }
                                        icon.with_animation(
                                            "status-busy",
                                            Animation::new(Duration::from_millis(1200)).repeat(),
                                            |icon, progress| {
                                                icon.opacity(
                                                    0.4 + 0.6
                                                        * (progress * std::f32::consts::PI).sin(),
                                                )
                                            },
                                        )
                                        .into_any_element()
                                    }),
                            )
                            .when(busy && failed, |tile| {
                                tile.child(
                                    div()
                                        .absolute()
                                        .top(px(4.))
                                        .right(px(4.))
                                        .size(px(4.))
                                        .rounded_full()
                                        .bg(rgb(0xff8a82)),
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
                        false,
                        !self.extracting
                            && !self.converting
                            && !self.preview_loading
                            && self.preview_error.is_none()
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
            .font_family("Segoe UI")
            .text_size(px(11.))
            .text_color(rgb(SECONDARY))
            .occlude()
            .when(self.status != "Ready", |view| {
                view.child(status_line(self.status.clone(), SECONDARY))
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
                    .enumerate()
                    .filter_map(|(depth, column)| {
                        if column.loading {
                            Some(
                                status_line(
                                    format!("Loading… · {}", column.folder.target.export_name()),
                                    ACCENT,
                                )
                                .into_any_element(),
                            )
                        } else {
                            column.error.as_ref().map(|error| {
                                div()
                                    .flex()
                                    .flex_shrink_0()
                                    .items_center()
                                    .gap_2()
                                    .child(status_line(error.clone(), 0xff8a82).flex_1().min_w_0())
                                    .child(button("retry-folder", "Retry", false, true).on_click(
                                        cx.listener(move |this, _, _, cx| {
                                            this.retry_column(depth, cx)
                                        }),
                                    ))
                                    .into_any_element()
                            })
                        }
                    }),
            )
            .when(self.preview_loading, |view| {
                let name = self.selected_item().map_or("", |item| item.name.as_str());
                view.child(status_line(format!("Preparing preview… · {name}"), ACCENT))
            })
            .when_some(self.preview_error.as_ref(), |view, error| {
                view.child(status_line(format!("Preview: {error}"), 0xff8a82))
            })
            .when(
                !self.preview_loading && self.preview_error.is_none(),
                |view| {
                    if let Some(item) = self.selected_item().filter(|_| self.preview.is_some()) {
                        view.child(status_line(
                            format!("Preview ready · {}", item.name),
                            SECONDARY,
                        ))
                    } else if let Some(column) = self
                        .columns
                        .last()
                        .filter(|column| !column.loading && column.error.is_none())
                    {
                        view.child(status_line(
                            format!("{} items", column.folder.items.len()),
                            SECONDARY,
                        ))
                    } else {
                        view
                    }
                },
            )
            .when(self.converting, |view| {
                view.child(status_line("Exporting…".into(), ACCENT))
            })
            .children(self.name_jobs.iter().map(|job| {
                div().flex().gap_2().items_center().child(
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
                    .flex_1(),
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
                .child(div().h(px(3.)).rounded_full().bg(rgb(BORDER)).child(
                    div().h_full().rounded_full().bg(rgb(ACCENT)).w(relative(
                        if self.progress.total == 0 {
                            0.
                        } else {
                            self.progress.completed as f32 / self.progress.total as f32
                        },
                    )),
                ))
            })
            .child(self.status_actions(cx))
            .when(self.show_errors && !self.errors.is_empty(), |view| {
                view.child(
                    uniform_list(
                        "error-list",
                        self.errors.len(),
                        cx.processor(|this, range: Range<usize>, _, cx| {
                            range
                                .map(|index| {
                                    div()
                                        .id(("error", index))
                                        .h(px(28.))
                                        .px_2()
                                        .text_color(rgb(0xff8a82))
                                        .truncate()
                                        .cursor_pointer()
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            cx.write_to_clipboard(ClipboardItem::new_string(
                                                this.errors[index].clone(),
                                            ));
                                        }))
                                        .child(this.errors[index].clone())
                                })
                                .collect()
                        }),
                    )
                    .track_scroll(self.error_scroll.clone())
                    .h(px(140.))
                    .flex_shrink_0()
                    .map(|view| {
                        scroll::wheel(
                            view,
                            Some(self.error_scroll.0.borrow().base_handle.clone()),
                            None,
                        )
                    }),
                )
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
            .when(!self.errors.is_empty(), |view| {
                view.child(
                    button(
                        "errors",
                        format!("Errors ({})", self.errors.len()),
                        self.show_errors,
                        true,
                    )
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.show_errors = !this.show_errors;
                        cx.notify();
                    })),
                )
            })
            .child(div().flex_1())
            .child(
                button("close-status", "×", false, true).on_click(cx.listener(|this, _, _, cx| {
                    this.show_status = false;
                    cx.notify();
                })),
            )
    }
}

fn status_line(text: String, color: u32) -> Div {
    div().flex_shrink_0().text_color(rgb(color)).child(text)
}
