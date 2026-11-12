//! Finder-style columns, toolbar, and floating path navigation.

use super::filename::filename;
use super::view::{button, bytes_label, shortcut, spinner, tool_button, tooltip};
use super::*;
use crate::icons::{file_icon, glyph};

impl Workspace {
    pub(super) fn toolbar(&self, window: &Window, cx: &mut Context<Self>) -> impl IntoElement {
        crate::titlebar::bar(window)
            .child(
                tool_button(
                    "home",
                    "icons/home.svg",
                    false,
                    !self.columns[0].folder.items.is_empty(),
                )
                .occlude()
                .tooltip(tooltip("Opened items (Alt+Home)"))
                .on_click(cx.listener(|this, _, window, cx| this.home(&Home, window, cx))),
            )
            .child(
                tool_button(
                    "back",
                    "icons/chevron-left.svg",
                    false,
                    self.active > 0 || self.columns.len() > 1,
                )
                .occlude()
                .tooltip(tooltip("Back (Alt+←)"))
                .on_click(cx.listener(|this, _, window, cx| this.back(&Back, window, cx))),
            )
            .child(div().w(px(1.)).h(px(16.)).mx_1().bg(rgb(BORDER)))
            .child(
                tool_button("open-folder", "icons/folder-open.svg", false, true)
                    .pr(px(10.))
                    .child("Open folder…")
                    .occlude()
                    .tooltip(tooltip(shortcut("Shift+O")))
                    .on_click(cx.listener(|this, _, _, cx| this.path_dialog(true, cx))),
            )
            .child(
                tool_button("open-files", "icons/file-plus.svg", false, true)
                    .pr(px(10.))
                    .child("Files…")
                    .occlude()
                    .tooltip(tooltip(shortcut("O")))
                    .on_click(
                        cx.listener(|this, _, window, cx| this.open_dialog(&Open, window, cx)),
                    ),
            )
            .child(crate::titlebar::drag_space())
            .child(
                tool_button(
                    "gen-dataset",
                    "icons/dataset.svg",
                    false,
                    !self.extracting && !self.converting && self.dataset_game().is_some(),
                )
                .pr(px(10.))
                .child("Gen Dataset")
                .occlude()
                .tooltip(tooltip("Generate a dialogue dataset for the current game"))
                .on_click(cx.listener(|this, _, _, cx| this.dataset_dialog(cx))),
            )
            .child(
                tool_button(
                    "export",
                    "icons/export.svg",
                    self.show_export_menu,
                    !self.extracting,
                )
                .pr(px(10.))
                .child("Export…")
                .occlude()
                .on_hover(cx.listener(|this, hovered, _, _| {
                    this.export_button_hovered = *hovered;
                }))
                .on_click(cx.listener(|this, _, window, cx| {
                    if !this.extracting {
                        this.path_menu = None;
                        this.show_export_menu = !this.show_export_menu;
                        window.focus(if this.show_export_menu {
                            &this.focus
                        } else {
                            &this.browser_focus
                        });
                        cx.notify();
                    }
                })),
            )
            .child(
                tool_button(
                    "inspector",
                    "icons/sidebar.svg",
                    self.show_inspector && self.selection.is_some(),
                    self.preview_selection().is_some(),
                )
                .occlude()
                .tooltip(tooltip(format!("Preview ({})", shortcut("I"))))
                .on_click(
                    cx.listener(|this, _, window, cx| {
                        this.toggle_inspector(&Inspector, window, cx)
                    }),
                ),
            )
            .child(
                tool_button("settings", "icons/settings.svg", false, true)
                    .occlude()
                    .tooltip(tooltip(format!("Settings ({})", shortcut(","))))
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.toggle_settings(&Settings, window, cx)
                    })),
            )
            .child(crate::titlebar::controls(window))
    }

    pub(super) fn welcome(&self, cx: &mut Context<Self>) -> impl IntoElement {
        // Drops are handled by the workspace root; this only highlights the target.
        div()
            .absolute()
            .inset_0()
            .p(px(24.))
            .pb(px(66.))
            .flex()
            .items_center()
            .justify_center()
            .child(
                div()
                    .id("welcome")
                    .w_full()
                    .max_w(px(460.))
                    .px(px(28.))
                    .py(px(36.))
                    .rounded(px(14.))
                    .border_1()
                    .border_dashed()
                    .border_color(rgb(BORDER))
                    .bg(rgba(0xffffff05))
                    .flex()
                    .flex_col()
                    .items_center()
                    .gap_3()
                    .drag_over::<ExternalPaths>(|style, _, _, _| {
                        style.border_color(rgb(ACCENT)).bg(rgba(0x0a84ff14))
                    })
                    .child(
                        div()
                            .size(px(56.))
                            .rounded(px(14.))
                            .bg(rgba(0x0a84ff1f))
                            .flex()
                            .items_center()
                            .justify_center()
                            .child(glyph("icons/import.svg", 28., ACCENT_TEXT)),
                    )
                    .child(
                        div()
                            .mt_1()
                            .text_size(px(16.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child("Open game resources"),
                    )
                    .child(
                        div()
                            .text_center()
                            .text_color(rgb(SECONDARY))
                            .child("Drop game folders, archives or files here, or choose them."),
                    )
                    .child(
                        div()
                            .mt_2()
                            .flex()
                            .gap_2()
                            .child(
                                button("welcome-folder", "Open folder…", true, true).on_click(
                                    cx.listener(|this, _, _, cx| this.path_dialog(true, cx)),
                                ),
                            )
                            .child(
                                button("welcome-files", "Open files…", false, true).on_click(
                                    cx.listener(|this, _, window, cx| {
                                        this.open_dialog(&Open, window, cx)
                                    }),
                                ),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_4()
                            .text_size(px(11.))
                            .text_color(rgb(TERTIARY))
                            .child(format!("{} folder", shortcut("Shift+O")))
                            .child(format!("{} files", shortcut("O"))),
                    ),
            )
    }

    pub(super) fn export_menu(&self, cx: &mut Context<Self>) -> impl IntoElement {
        glass()
            .id("export-menu")
            .absolute()
            .top(px(crate::titlebar::HEIGHT - 6.))
            .right(px(12.))
            .w(px(230.))
            .p(px(4.))
            .rounded(px(10.))
            .flex()
            .flex_col()
            .gap(px(2.))
            .occlude()
            .on_mouse_down_out(cx.listener(|this, _, window, cx| {
                // The toolbar button toggles the menu itself on click.
                if this.export_button_hovered {
                    return;
                }
                this.show_export_menu = false;
                window.focus(&this.browser_focus);
                cx.notify();
            }))
            .child(
                menu_item(
                    "export-folder",
                    Some("icons/folder.svg"),
                    "Export folder…",
                    self.columns.len() > 1,
                )
                .on_click(cx.listener(|this, _, _, cx| this.export_dialog(false, cx))),
            )
            .child(
                menu_item(
                    "export-file",
                    Some("icons/file.svg"),
                    "Export selected file…",
                    self.selection.is_some(),
                )
                .on_click(cx.listener(|this, _, _, cx| this.export_dialog(true, cx))),
            )
            .child(div().my(px(3.)).mx(px(6.)).h(px(1.)).bg(rgb(BORDER)))
            .child(
                menu_item("raw", self.raw.then_some("icons/check.svg"), "Raw", true).on_click(
                    cx.listener(|this, _, _, cx| {
                        this.raw = !this.raw;
                        cx.notify();
                    }),
                ),
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
                    .relative()
                    .flex_1()
                    .min_h_0()
                    .child(
                        uniform_list(
                            ("items", id),
                            column.folder.items.len(),
                            cx.processor(move |this, range: Range<usize>, _, cx| {
                                range
                                    .map(|row| {
                                        let column = &this.columns[depth];
                                        let item = &column.folder.items[row];
                                        let selected = column.selected == Some(row);
                                        let active = depth == this.active;
                                        let group = if let Target::ArchiveSet(set, _) = &item.target
                                        {
                                            Some(set)
                                        } else {
                                            None
                                        };
                                        let meta = item
                                            .count
                                            .map(|n| {
                                                if group.is_some() {
                                                    format!("{n} files")
                                                } else {
                                                    n.to_string()
                                                }
                                            })
                                            .or_else(|| item.size.map(bytes_label))
                                            .unwrap_or_default();
                                        let highlighted = selected && active;
                                        let background = if !selected {
                                            if group.is_some() {
                                                rgba(0xffffff0a)
                                            } else {
                                                rgba(0)
                                            }
                                        } else if active {
                                            rgb(ACCENT)
                                        } else {
                                            rgba(0xffffff1f)
                                        };
                                        let muted =
                                            if highlighted { 0xffffffc7 } else { 0xffffff6b };
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
                                                .when_some(group, |view, set| {
                                                    let mut description = set
                                                        .members
                                                        .iter()
                                                        .map(|path| {
                                                            path.file_name()
                                                                .unwrap_or_default()
                                                                .to_string_lossy()
                                                                .into_owned()
                                                        })
                                                        .collect::<Vec<_>>()
                                                        .join("\n");
                                                    if let Some(size) = item.size {
                                                        description.push_str(&format!(
                                                            "\n{}",
                                                            bytes_label(size)
                                                        ));
                                                    }
                                                    view.border_1()
                                                        .border_color(rgba(0xffffff24))
                                                        .tooltip(tooltip(description))
                                                })
                                                .cursor_pointer()
                                                .bg(background)
                                                .hover(move |style| {
                                                    style.bg(if selected {
                                                        background
                                                    } else {
                                                        rgba(0xffffff0d)
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
                                                .child(file_icon(item, highlighted))
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
                                                        .text_color(rgba(muted))
                                                        .child(meta),
                                                )
                                                .when(item.container, |view| {
                                                    view.child(
                                                        svg()
                                                            .path("icons/chevron-right.svg")
                                                            .size(px(11.))
                                                            .flex_shrink_0()
                                                            .text_color(rgba(muted)),
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
                    )
                    .when_some(self.column_placeholder(depth), |view, placeholder| {
                        view.child(placeholder)
                    }),
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

    /// Loading and empty states for nested columns. Failures and retry stay in
    /// the status panel; the root column is covered by the welcome view.
    fn column_placeholder(&self, depth: usize) -> Option<AnyElement> {
        let column = &self.columns[depth];
        let content = if column.loading {
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(spinner(("column-loading", column.id), 13., SECONDARY))
                .child("Loading…")
        } else if depth > 0 && !column.failed && column.folder.items.is_empty() {
            div().child("No items")
        } else {
            return None;
        };
        Some(
            div()
                .absolute()
                .inset_0()
                .pb(px(50.))
                .px_3()
                .flex()
                .items_center()
                .justify_center()
                .text_size(px(12.))
                .text_color(rgb(SECONDARY))
                .child(content)
                .into_any_element(),
        )
    }

    pub(super) fn path_bar(&self, window: &Window, cx: &mut Context<Self>) -> impl IntoElement {
        let text_style = TextStyle {
            font_family: UI_FONT.into(),
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
                Target::ArchiveSet(set, _) => {
                    path = set.primary.display().to_string();
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
                    .child(glyph("icons/home.svg", 12., SECONDARY))
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
                            .child(glyph("icons/chevron-right.svg", 9., TERTIARY).mx(px(1.)))
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
                                        TEXT
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
                menu_item("copy-path", Some("icons/copy.svg"), "Copy path", true).on_click(
                    cx.listener(move |this, _, window, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(path.clone()));
                        this.path_menu = None;
                        window.focus(&this.browser_focus);
                        cx.notify();
                    }),
                ),
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
        .bg(rgba(0x2a2a2df2))
        .border_1()
        .border_color(rgba(0xffffff24))
        .shadow_lg()
}

/// A full-width menu row with a fixed glyph slot so labels stay aligned.
fn menu_item(
    id: &'static str,
    icon: Option<&'static str>,
    label: &'static str,
    enabled: bool,
) -> Stateful<Div> {
    let color = if enabled { TEXT } else { DISABLED };
    div()
        .id(id)
        .h(px(28.))
        .px(px(8.))
        .rounded(px(6.))
        .flex()
        .items_center()
        .gap(px(8.))
        .whitespace_nowrap()
        .text_color(rgb(color))
        .child(
            div()
                .size(px(15.))
                .flex_shrink_0()
                .when_some(icon, |slot, icon| slot.child(glyph(icon, 15., color))),
        )
        .child(label)
        .when(enabled, |item| {
            item.cursor_pointer()
                .hover(|style| style.bg(rgba(0x0a84ffcc)))
        })
        .when(!enabled, |item| {
            item.occlude()
                .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
        })
}
