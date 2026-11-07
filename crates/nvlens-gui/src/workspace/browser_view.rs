//! Finder-style columns, toolbar, and floating path navigation.

use super::filename::filename;
use super::view::{button, bytes_label};
use super::*;
use crate::icons::file_icon;

impl Workspace {
    pub(super) fn toolbar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .h(px(52.))
            .flex_shrink_0()
            .px(px(12.))
            .flex()
            .items_center()
            .gap_2()
            .border_b_1()
            .border_color(rgb(BORDER))
            .child(
                button("home", "⌂", false, !self.columns[0].folder.items.is_empty())
                    .on_click(cx.listener(|this, _, window, cx| this.home(&Home, window, cx))),
            )
            .child(
                button(
                    "back",
                    "‹",
                    false,
                    self.active > 0 || self.columns.len() > 1,
                )
                .on_click(cx.listener(|this, _, window, cx| this.back(&Back, window, cx))),
            )
            .child(
                button("open-folder", "Open folder…", false, true)
                    .on_click(cx.listener(|this, _, _, cx| this.path_dialog(true, cx))),
            )
            .child(
                button("open-files", "Files…", false, true).on_click(
                    cx.listener(|this, _, window, cx| this.open_dialog(&Open, window, cx)),
                ),
            )
            .child(div().flex_1())
            .child(
                button("export", "Export…", self.show_export_menu, !self.extracting).on_click(
                    cx.listener(|this, _, window, cx| {
                        if !this.extracting {
                            this.path_menu = None;
                            this.show_export_menu = true;
                            window.focus(&this.focus);
                            cx.notify();
                        }
                    }),
                ),
            )
            .child(
                button("inspector", "Preview", self.show_inspector, true).on_click(
                    cx.listener(|this, _, window, cx| {
                        this.toggle_inspector(&Inspector, window, cx)
                    }),
                ),
            )
            .child(button("settings", "Settings", false, true).on_click(
                cx.listener(|this, _, window, cx| this.toggle_settings(&Settings, window, cx)),
            ))
    }

    pub(super) fn export_menu(&self, cx: &mut Context<Self>) -> impl IntoElement {
        glass()
            .id("export-menu")
            .absolute()
            .top(px(46.))
            .right(px(12.))
            .w(px(230.))
            .p_2()
            .rounded(px(10.))
            .flex()
            .flex_col()
            .gap_2()
            .occlude()
            .on_mouse_down_out(cx.listener(|this, _, window, cx| {
                this.show_export_menu = false;
                window.focus(&this.browser_focus);
                cx.notify();
            }))
            .child(
                button(
                    "export-folder",
                    "Export folder…",
                    false,
                    self.columns.len() > 1,
                )
                .on_click(cx.listener(|this, _, _, cx| this.export_dialog(false, cx))),
            )
            .child(
                button(
                    "export-file",
                    "Export selected file…",
                    false,
                    self.selection.is_some(),
                )
                .on_click(cx.listener(|this, _, _, cx| this.export_dialog(true, cx))),
            )
            .child(
                button(
                    "raw",
                    if self.raw { "✓ Raw" } else { "Raw" },
                    self.raw,
                    true,
                )
                .on_click(cx.listener(|this, _, _, cx| {
                    this.raw = !this.raw;
                    cx.notify();
                })),
            )
            .with_animation(
                "export-menu-enter",
                Animation::new(Duration::from_millis(140)).with_easing(ease_in_out),
                |view, progress| view.opacity(progress),
            )
    }

    pub(super) fn browser(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .id("column-strip")
            .size_full()
            .flex()
            .overflow_x_scroll()
            .track_scroll(&self.strip_scroll)
            .key_context("Browser")
            .track_focus(&self.browser_focus)
            .on_action(
                cx.listener(|this, _: &MoveUp, window, cx| this.move_selection(false, window, cx)),
            )
            .on_action(
                cx.listener(|this, _: &MoveDown, window, cx| this.move_selection(true, window, cx)),
            )
            .on_action(cx.listener(Self::enter_nested))
            .children(
                (0..self.columns.len()).map(|depth| self.column(depth, cx).into_any_element()),
            )
            .child(div().flex_1().min_w(px(24.)).h_full())
            .map(|view| scroll::wheel(view, None, Some(self.strip_scroll.clone())))
    }

    fn column(&self, depth: usize, cx: &mut Context<Self>) -> impl IntoElement {
        let column = &self.columns[depth];
        let id = column.id;
        div()
            .id(("column", id))
            .relative()
            .w(column.width)
            .flex_shrink_0()
            .h_full()
            .flex()
            .flex_col()
            .border_r_1()
            .border_color(rgba(0xffffff1a))
            .when(depth == 0, |view| view.bg(rgba(0xffffff05)))
            .on_hover(cx.listener(move |this, hovered, _, cx| {
                if let Some(column) = this.columns.iter_mut().find(|column| column.id == id) {
                    column.hovered = *hovered;
                    cx.notify();
                }
            }))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, _, cx| {
                    if this.active != depth {
                        this.activate(depth, cx);
                    }
                }),
            )
            .child(
                div()
                    .h(px(32.))
                    .flex_shrink_0()
                    .px(px(8.))
                    .flex()
                    .items_center()
                    .justify_end()
                    .child(
                        div()
                            .id(("filter", id))
                            .size(px(24.))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded(px(6.))
                            .cursor_pointer()
                            .text_color(rgb(if column.filter_open {
                                0x8dbdff
                            } else {
                                SECONDARY
                            }))
                            .hover(|s| s.bg(rgba(0xffffff1f)))
                            .on_click(cx.listener(move |this, _, window, cx| {
                                if this.columns[depth].filter_open {
                                    this.columns[depth].filter_open = false;
                                    this.columns[depth]
                                        .filter
                                        .update(cx, |input, cx| input.clear(cx));
                                    window.focus(&this.browser_focus);
                                    cx.notify();
                                } else {
                                    this.focus_filter(depth, window, cx);
                                }
                            }))
                            .child("⌕"),
                    ),
            )
            .when(column.filter_open, |view| {
                view.child(div().mx(px(8.)).mb(px(6.)).child(column.filter.clone()))
            })
            .child(
                div()
                    .relative()
                    .flex_1()
                    .min_h_0()
                    .child(
                        uniform_list(
                            ("items", id),
                            column.visible.len(),
                            cx.processor(move |this, range: Range<usize>, _, cx| {
                                range
                                    .map(|position| {
                                        let column = &this.columns[depth];
                                        let row = column.visible[position];
                                        let item = &column.folder.items[row];
                                        let selected = column.selected == Some(row);
                                        let active = depth == this.active;
                                        let meta = item
                                            .count
                                            .map(|n| n.to_string())
                                            .or_else(|| item.size.map(bytes_label))
                                            .unwrap_or_default();
                                        div().h(px(26.)).w_full().px(px(6.)).child(
                                            div()
                                                .id(("row", row))
                                                .h_full()
                                                .w_full()
                                                .px(px(7.))
                                                .flex()
                                                .items_center()
                                                .gap(px(7.))
                                                .rounded(px(6.))
                                                .cursor_pointer()
                                                .bg(if selected {
                                                    if active {
                                                        rgb(ACCENT)
                                                    } else {
                                                        rgba(0xffffff1f)
                                                    }
                                                } else {
                                                    rgba(0)
                                                })
                                                .hover(move |style| {
                                                    style.bg(if selected {
                                                        if active {
                                                            rgb(ACCENT)
                                                        } else {
                                                            rgba(0xffffff1f)
                                                        }
                                                    } else {
                                                        rgba(0xffffff09)
                                                    })
                                                })
                                                .on_click(cx.listener(
                                                    move |this, event: &ClickEvent, window, cx| {
                                                        window.focus(&this.browser_focus);
                                                        this.select(depth, row, cx);
                                                        if event.click_count() == 2 {
                                                            this.enter_nested(&Enter, window, cx);
                                                        }
                                                    },
                                                ))
                                                .child(file_icon(item, selected && active))
                                                .child(
                                                    div()
                                                        .flex_1()
                                                        .min_w_0()
                                                        .overflow_hidden()
                                                        .child(filename(&item.name)),
                                                )
                                                .child(
                                                    div()
                                                        .flex_shrink_0()
                                                        .text_size(px(11.))
                                                        .text_color(if selected && active {
                                                            rgba(0xffffffc7)
                                                        } else {
                                                            rgba(0xffffff6b)
                                                        })
                                                        .child(meta),
                                                )
                                                .when(item.container, |view| {
                                                    view.child(
                                                        div()
                                                            .flex_shrink_0()
                                                            .text_size(px(15.))
                                                            .text_color(if selected && active {
                                                                rgba(0xffffffc7)
                                                            } else {
                                                                rgba(0xffffff6b)
                                                            })
                                                            .child("›"),
                                                    )
                                                }),
                                        )
                                    })
                                    .collect()
                            }),
                        )
                        .track_scroll(column.scroll.clone())
                        .size_full()
                        .pr(px(14.))
                        .pb(px(50.)),
                    )
                    .when(
                        column.loading
                            || column.error.is_some()
                            || (column.visible.is_empty()
                                && (!column.folder.items.is_empty()
                                    || !matches!(column.folder.target, Target::Opened))),
                        |view| {
                            view.child(
                                div()
                                    .absolute()
                                    .top(px(10.))
                                    .left(px(12.))
                                    .right(px(12.))
                                    .py_4()
                                    .flex()
                                    .flex_col()
                                    .items_center()
                                    .gap_2()
                                    .text_size(px(12.))
                                    .text_color(rgb(SECONDARY))
                                    .child(column.error.clone().unwrap_or_else(|| {
                                        if column.loading {
                                            "Loading…"
                                        } else if !column.filter.read(cx).value().is_empty() {
                                            "No matching items"
                                        } else {
                                            "No items"
                                        }
                                        .into()
                                    }))
                                    .when(column.error.is_some(), |view| {
                                        view.child(button("retry", "Retry", false, true).on_click(
                                            cx.listener(move |this, _, _, cx| {
                                                this.retry_column(depth, cx)
                                            }),
                                        ))
                                    }),
                            )
                        },
                    )
                    .child(
                        column
                            .scrollbar
                            .render(
                                column.scroll.0.borrow().base_handle.clone(),
                                column.hovered,
                                Axis::Vertical,
                            )
                            .top(px(2.))
                            .bottom(px(54.))
                            .right(px(6.))
                            .w(px(10.)),
                    ),
            )
            .child(
                div()
                    .id(("resize", id))
                    .absolute()
                    .top_0()
                    .bottom_0()
                    .right_0()
                    .w(px(5.))
                    .cursor(CursorStyle::ResizeColumn)
                    .hover(|s| s.bg(rgba(0x0a84ff80)))
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, event: &MouseDownEvent, _, cx| {
                            this.resizing = Some((
                                ResizeTarget::Column(id),
                                event.position.x,
                                this.columns[depth].width,
                            ));
                            cx.stop_propagation();
                        }),
                    )
                    .on_click(cx.listener(move |this, event: &ClickEvent, _, cx| {
                        if event.click_count() == 2 {
                            this.columns[depth].width = px(COLUMN_WIDTH);
                            cx.notify();
                        }
                    })),
            )
            .map(|view| {
                scroll::wheel(
                    view.with_animation(
                        ("column-enter", id),
                        Animation::new(Duration::from_millis(180)).with_easing(ease_in_out),
                        |view, progress| view.opacity(progress),
                    ),
                    Some(column.scroll.0.borrow().base_handle.clone()),
                    Some(self.strip_scroll.clone()),
                )
            })
    }

    pub(super) fn path_bar(&self, window: &Window, cx: &mut Context<Self>) -> impl IntoElement {
        let text_style = TextStyle {
            font_family: "Segoe UI".into(),
            font_size: px(10.).into(),
            ..TextStyle::default()
        };
        let mut segments = Vec::new();
        let mut path = String::new();
        for (depth, column) in self.columns.iter().enumerate().take(self.active + 1) {
            let Some(item) = column.selected.and_then(|row| column.folder.items.get(row)) else {
                break;
            };
            match &item.target {
                Target::Directory(location, _) | Target::File(location, _) => {
                    path = location.display().to_string();
                }
                _ => {
                    path.push('/');
                    path.push_str(&item.name);
                }
            }
            segments.push((depth, item, path.clone()));
        }
        glass()
            .id("path-bar")
            .min_w_0()
            .rounded(px(10.))
            .px(px(5.))
            .py(px(3.))
            .flex()
            .items_center()
            .overflow_x_scroll()
            .track_scroll(&self.path_scroll)
            .font_family(text_style.font_family.clone())
            .text_size(px(10.))
            .occlude()
            .child(
                div()
                    .id("path-root")
                    .flex_shrink_0()
                    .h(px(22.))
                    .px(px(6.))
                    .flex()
                    .items_center()
                    .gap(px(5.))
                    .rounded(px(6.))
                    .cursor_pointer()
                    .whitespace_nowrap()
                    .hover(|s| s.bg(rgba(0xffffff1f)))
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.home(&Home, window, cx);
                    }))
                    .child("▤")
                    .child("Opened"),
            )
            .children(
                segments
                    .iter()
                    .enumerate()
                    .map(|(index, (depth, item, path))| {
                        let depth = *depth;
                        let path = path.clone();
                        let name = filename(&item.name);
                        // Reserve the full measured name plus icon, gap and padding.
                        // The whole breadcrumb strip scrolls instead of squeezing names.
                        let width =
                            (name.natural_width(&text_style, window) + px(34.)).min(px(880.));
                        div()
                            .flex()
                            .items_center()
                            .flex_shrink_0()
                            .child(div().mx(px(1.)).text_color(rgb(SECONDARY)).child("›"))
                            .child(
                                div()
                                    .id(("path", depth))
                                    .w(width)
                                    .flex_shrink_0()
                                    .h(px(22.))
                                    .px(px(6.))
                                    .flex()
                                    .items_center()
                                    .gap(px(5.))
                                    .rounded(px(6.))
                                    .cursor_pointer()
                                    .text_color(rgb(if index + 1 == segments.len() {
                                        0xf5f5f7
                                    } else {
                                        SECONDARY
                                    }))
                                    .hover(|s| s.bg(rgba(0xffffff1f)))
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.collapse_path(depth, window, cx);
                                    }))
                                    .on_mouse_down(
                                        MouseButton::Right,
                                        cx.listener(
                                            move |this, event: &MouseDownEvent, window, cx| {
                                                this.open_path_menu(
                                                    path.clone(),
                                                    event.position,
                                                    window,
                                                    cx,
                                                );
                                            },
                                        ),
                                    )
                                    .child(file_icon(item, false))
                                    .child(div().flex_1().min_w_0().overflow_hidden().child(name)),
                            )
                    }),
            )
            .map(|view| scroll::wheel(view, None, Some(self.path_scroll.clone())))
    }

    fn open_path_menu(
        &mut self,
        path: String,
        position: Point<Pixels>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.show_export_menu = false;
        self.path_menu = Some((path, position));
        window.focus(&self.focus);
        cx.stop_propagation();
        cx.notify();
    }

    pub(super) fn path_context_menu(
        &self,
        path: String,
        position: Point<Pixels>,
        window: &Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let viewport = window.viewport_size();
        let width = px(160.);
        let height = px(38.);
        let top = if position.y + height + px(8.) <= viewport.height {
            position.y
        } else {
            position.y - height
        };
        glass()
            .id("path-context-menu")
            .absolute()
            .left(position.x.min(viewport.width - width - px(8.)).max(px(8.)))
            .top(top.max(px(8.)))
            .w(width)
            .p(px(4.))
            .rounded(px(10.))
            .occlude()
            .on_mouse_down_out(cx.listener(|this, _, window, cx| {
                this.path_menu = None;
                window.focus(&this.browser_focus);
                cx.notify();
            }))
            .child(
                button("copy-path", "Copy path", false, true).on_click(cx.listener(
                    move |this, _, window, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(path.clone()));
                        this.path_menu = None;
                        window.focus(&this.browser_focus);
                        cx.notify();
                    },
                )),
            )
            .with_animation(
                "path-menu-enter",
                Animation::new(Duration::from_millis(140)).with_easing(ease_in_out),
                |view, progress| view.opacity(progress),
            )
    }
}

pub(super) fn glass() -> Div {
    div()
        .bg(rgba(0x262629ee))
        .border_1()
        .border_color(rgba(0xffffff29))
        .shadow_lg()
}
