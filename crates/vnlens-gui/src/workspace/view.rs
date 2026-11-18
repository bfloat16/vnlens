//! Column browser, inspector, and desktop controls.

use super::*;

impl Workspace {
    fn settings(&self, window: &Window, cx: &mut Context<Self>) -> impl IntoElement {
        let enabled = self.preferences.virtual_paths();
        let progress = self.path_switch_changed.map_or(1., |changed| {
            (changed.elapsed().as_secs_f32() / 0.18).min(1.)
        });
        if progress < 1. {
            window.request_animation_frame();
        }
        let progress = ease_in_out(progress);
        let position = if enabled { progress } else { 1. - progress };
        div()
            .relative()
            .size_full()
            .bg(rgb(BACKGROUND))
            .text_color(rgb(TEXT))
            .font_family(UI_FONT)
            .text_size(px(13.))
            .key_context("Workspace")
            .track_focus(&self.focus)
            .on_action(cx.listener(Self::toggle_settings))
            .on_action(cx.listener(Self::cancel))
            .child(
                crate::titlebar::bar(window)
                    .child(
                        tool_button("close-settings", "icons/chevron-left.svg", false, true)
                            .occlude()
                            .tooltip(tooltip("Back to browser (Esc)"))
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.toggle_settings(&Settings, window, cx)
                            })),
                    )
                    .child(div().font_weight(FontWeight::SEMIBOLD).child("Settings"))
                    .child(crate::titlebar::drag_space())
                    .child(crate::titlebar::controls(window)),
            )
            .child(
                div().flex().justify_center().px_4().pt(px(28.)).child(
                    div()
                        .w_full()
                        .max_w(px(640.))
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(
                            div()
                                .px_1()
                                .text_size(px(11.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(SECONDARY))
                                .child("BROWSING"),
                        )
                        .child(
                            div()
                                .px_4()
                                .py_3()
                                .rounded(px(10.))
                                .bg(rgb(PANEL))
                                .border_1()
                                .border_color(rgb(BORDER))
                                .flex()
                                .items_center()
                                .gap_4()
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .child("Virtual script paths")
                                        .child(
                                            div()
                                                .mt_1()
                                                .text_size(px(12.))
                                                .text_color(rgb(SECONDARY))
                                                .child(
                                                    "Use original script folders and names \
                                                     instead of archive entry paths.",
                                                ),
                                        ),
                                )
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .text_color(rgb(SECONDARY))
                                        .child(if enabled { "Virtual" } else { "Real" }),
                                )
                                .child(
                                    div()
                                        .id("virtual-script-paths")
                                        .relative()
                                        .w(px(44.))
                                        .h(px(24.))
                                        .flex_shrink_0()
                                        .rounded_full()
                                        .cursor_pointer()
                                        .bg(rgb(if enabled { ACCENT } else { CONTROL_HOVER }))
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.toggle_virtual_paths(cx)
                                        }))
                                        .child(
                                            div()
                                                .absolute()
                                                .left(px(2. + 20. * position))
                                                .top(px(2.))
                                                .size(px(20.))
                                                .rounded_full()
                                                .bg(rgb(0xffffff))
                                                .shadow_sm(),
                                        ),
                                ),
                        )
                        .child(
                            div()
                                .px_4()
                                .py_3()
                                .rounded(px(10.))
                                .bg(rgb(PANEL))
                                .border_1()
                                .border_color(rgb(BORDER))
                                .flex()
                                .items_center()
                                .gap_4()
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .child("Compose PIMG images")
                                        .child(
                                            div()
                                                .mt_1()
                                                .text_size(px(12.))
                                                .text_color(rgb(SECONDARY))
                                                .child("Combine visible layers for image preview and PNG export."),
                                        ),
                                )
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .text_color(rgb(SECONDARY))
                                        .child(if self.preferences.compose_pimg() { "Image" } else { "Archive" }),
                                )
                                .child(
                                    div()
                                        .id("compose-pimg")
                                        .relative()
                                        .w(px(44.))
                                        .h(px(24.))
                                        .flex_shrink_0()
                                        .rounded_full()
                                        .cursor_pointer()
                                        .bg(rgb(if self.preferences.compose_pimg() { ACCENT } else { CONTROL_HOVER }))
                                        .on_click(cx.listener(|this, _, _, cx| this.toggle_compose_pimg(cx)))
                                        .child(
                                            div()
                                                .absolute()
                                                .left(px(if self.preferences.compose_pimg() { 22. } else { 2. }))
                                                .top(px(2.))
                                                .size(px(20.))
                                                .rounded_full()
                                                .bg(rgb(0xffffff))
                                                .shadow_sm(),
                                        ),
                                ),
                        ),
                ),
            )
            .child(self.status_dock(px(0.), window, cx))
    }

    fn inspector(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let scroll = self.preview_scroll.0.borrow().base_handle.clone();
        let scrollable = self
            .preview
            .as_ref()
            .is_some_and(|preview| preview.image.is_none() && preview.video.is_none());
        div()
            .size_full()
            .overflow_hidden()
            .pb(px(54.))
            .flex()
            .flex_col()
            .key_context("Preview")
            .track_focus(&self.preview_focus)
            .on_action(cx.listener(Self::copy_instruction))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, window, _| {
                    window.focus(&this.preview_focus);
                }),
            )
            .when_some(self.selected_item(), |view, item| {
                view.child(self.inspector_header(item))
            })
            .child(
                div()
                    .relative()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .flex_col()
                    .when(scrollable, |view| view.pr(px(16.)).pb(px(16.)))
                    .when(self.selection.is_some(), |view| {
                        view.child(self.preview_view(cx))
                    })
                    .when(scrollable, |view| {
                        view.child(
                            self.preview_vertical_bar
                                .render(scroll.clone(), true, Axis::Vertical)
                                .top(px(2.))
                                .bottom(px(16.))
                                .right(px(3.))
                                .w(px(10.)),
                        )
                        .child(
                            self.preview_horizontal_bar
                                .render(scroll.clone(), true, Axis::Horizontal)
                                .left(px(6.))
                                .right(px(16.))
                                .bottom(px(3.))
                                .h(px(10.)),
                        )
                    }),
            )
            .map(|view| {
                if scrollable {
                    scroll::wheel(view, Some(scroll.clone()), Some(scroll)).into_any_element()
                } else {
                    view.into_any_element()
                }
            })
    }

    fn inspector_header(&self, item: &Item) -> impl IntoElement {
        let mut details = vec![kind_label(item.kind).to_owned()];
        details.extend(item.size.map(bytes_label));
        div()
            .h(px(38.))
            .flex_shrink_0()
            .px_3()
            .flex()
            .items_center()
            .gap(px(8.))
            .border_b_1()
            .border_color(rgb(BORDER))
            .child(crate::icons::file_icon(item, false))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .font_weight(FontWeight::MEDIUM)
                    .child(super::filename::filename(&item.name)),
            )
            .when(self.raw, |view| {
                view.child(
                    div()
                        .flex_shrink_0()
                        .px(px(6.))
                        .py(px(1.))
                        .rounded(px(4.))
                        .bg(rgba(0x0a84ff2e))
                        .text_size(px(10.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(ACCENT_TEXT))
                        .child("RAW"),
                )
            })
            .child(
                div()
                    .flex_shrink_0()
                    .text_size(px(11.))
                    .text_color(rgb(SECONDARY))
                    .child(details.join(" · ")),
            )
    }

    fn preview_view(&self, cx: &mut Context<Self>) -> AnyElement {
        // Keep the completed image visible until its replacement is ready.
        // Loading, failure and retry controls belong to the status dock.
        let Some(preview) = &self.preview else {
            return div().into_any_element();
        };
        if let Some(table) = &preview.ir_table {
            return self.script_table(table, cx).into_any_element();
        }
        if let Some(audio) = &preview.audio {
            return self.audio_view(audio, cx).into_any_element();
        }
        if let Some(video) = &preview.video {
            return self.video_view(video, cx).into_any_element();
        }
        if preview.image.is_some() {
            return self.image_preview(cx);
        }
        if preview.model.is_some() {
            return self.model_preview(cx);
        }
        let text = preview.lines.is_some();
        let count = if text {
            preview.lines.as_ref().map_or(0, Vec::len)
        } else {
            preview.bytes.len().div_ceil(12)
        };
        // Gutter width follows the digit count of the last line number.
        let gutter = px(count.max(1).ilog10() as f32 * 7. + 7. + 16.);
        div()
            .flex_1()
            .min_h_0()
            .p_2()
            .child(
                uniform_list(
                    if text { "text-preview" } else { "hex-preview" },
                    count,
                    cx.processor(move |this, range: Range<usize>, _, _| {
                        let Some(preview) = &this.preview else {
                            return Vec::new();
                        };
                        range
                            .map(|index| {
                                let row = div()
                                    .h(px(22.))
                                    .flex()
                                    .items_center()
                                    .font_family(MONO_FONT)
                                    .text_size(px(11.))
                                    .whitespace_nowrap();
                                if text {
                                    let line = preview
                                        .lines
                                        .as_ref()
                                        .and_then(|lines| lines.get(index))
                                        .and_then(|range| {
                                            std::str::from_utf8(&preview.bytes[range.clone()]).ok()
                                        })
                                        .unwrap_or("")
                                        .trim_end_matches(['\r', '\n'])
                                        .replace('\t', "    ");
                                    return row
                                        .child(
                                            div()
                                                .w(gutter)
                                                .flex_shrink_0()
                                                .pr(px(12.))
                                                .flex()
                                                .justify_end()
                                                .text_color(rgb(TERTIARY))
                                                .child((index + 1).to_string()),
                                        )
                                        .child(line);
                                }
                                let start = index * 12;
                                let bytes =
                                    &preview.bytes[start..(start + 12).min(preview.bytes.len())];
                                let hex = bytes
                                    .iter()
                                    .map(|byte| format!("{byte:02X}"))
                                    .collect::<Vec<_>>()
                                    .join(" ");
                                let ascii: String = bytes
                                    .iter()
                                    .map(|&byte| {
                                        if byte.is_ascii_graphic() || byte == b' ' {
                                            char::from(byte)
                                        } else {
                                            '·'
                                        }
                                    })
                                    .collect();
                                row.gap(px(16.))
                                    .child(
                                        div()
                                            .text_color(rgb(TERTIARY))
                                            .child(format!("{start:08X}")),
                                    )
                                    // Pad short final rows so the ASCII column stays aligned.
                                    .child(format!("{hex:<35}"))
                                    .child(div().text_color(rgb(SECONDARY)).child(ascii))
                            })
                            .collect()
                    }),
                )
                .track_scroll(self.preview_scroll.clone())
                .with_width_from_item(Some(if text { preview.widest_line } else { 0 }))
                .with_horizontal_sizing_behavior(ListHorizontalSizingBehavior::Unconstrained)
                .size_full(),
            )
            .into_any_element()
    }
}

impl Render for Workspace {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self.show_settings {
            return self.settings(window, cx).into_any_element();
        }
        let inset = self.animate_layout(window);
        // Present pictures at display rate while playing; the event loop's
        // 33 ms tick alone would cap playback near 30 fps.
        if self.video_playing() {
            self.tick_video(cx);
            window.request_animation_frame();
        }
        div()
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(BACKGROUND))
            .text_color(rgb(TEXT))
            .font_family(UI_FONT)
            .text_size(px(13.))
            .key_context("Workspace")
            .track_focus(&self.focus)
            .on_action(cx.listener(Self::open_dialog))
            .on_action(cx.listener(|this, _: &TogglePlayback, _, cx| {
                if this.show_inspector {
                    if this
                        .preview
                        .as_ref()
                        .is_some_and(|preview| preview.video.is_some())
                    {
                        this.toggle_video(cx);
                    } else {
                        this.toggle_audio(cx);
                    }
                }
            }))
            .on_action(cx.listener(|this, _: &OpenFolder, _, cx| this.path_dialog(true, cx)))
            .on_action(cx.listener(Self::home))
            .on_action(cx.listener(Self::back))
            .on_action(cx.listener(Self::toggle_inspector))
            .on_action(cx.listener(Self::toggle_settings))
            .on_action(cx.listener(Self::cancel))
            .on_action(cx.listener(|this, _: &Export, _, cx| this.export_dialog(false, cx)))
            .on_drop(cx.listener(|this, paths: &ExternalPaths, _, cx| {
                this.open_paths(paths.paths().to_vec(), cx)
            }))
            .on_mouse_move(cx.listener(|this, event: &MouseMoveEvent, window, cx| {
                if let Some((target, start, width)) = this.resizing {
                    match target {
                        ResizeTarget::Column(id) => {
                            if let Some(column) =
                                this.columns.iter_mut().find(|column| column.id == id)
                            {
                                column.width =
                                    (width + event.position.x - start).clamp(px(180.), px(900.));
                            }
                        }
                        ResizeTarget::Inspector => {
                            let maximum = (window.viewport_size().width - px(180.)).max(px(180.));
                            this.inspector_width =
                                Some((width + start - event.position.x).clamp(px(180.), maximum));
                        }
                    }
                    cx.notify();
                }
            }))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| {
                    this.resizing = None;
                    cx.notify();
                }),
            )
            .on_mouse_up_out(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| {
                    this.resizing = None;
                    cx.notify();
                }),
            )
            .child(self.toolbar(window, cx))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .child(
                        div()
                            .relative()
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .overflow_hidden()
                            .child(self.browser(cx))
                            .when(
                                self.columns.len() == 1 && self.columns[0].folder.items.is_empty(),
                                |view| view.child(self.welcome(cx)),
                            ),
                    )
                    .when(inset > px(0.), |view| {
                        view.child(
                            div()
                                .relative()
                                .w(inset)
                                .h_full()
                                .flex_shrink_0()
                                .border_l_1()
                                .border_color(rgb(BORDER))
                                .bg(rgb(PANEL))
                                .overflow_hidden()
                                .child(self.inspector(cx))
                                .child(
                                    div()
                                        .id("resize-inspector")
                                        .absolute()
                                        .top_0()
                                        .bottom_0()
                                        .left_0()
                                        .w(px(5.))
                                        .cursor(CursorStyle::ResizeColumn)
                                        .hover(|s| s.bg(rgba(0x0a84ff80)))
                                        .on_mouse_down(
                                            MouseButton::Left,
                                            cx.listener(
                                                move |this, event: &MouseDownEvent, _, cx| {
                                                    this.inspector_width = Some(inset);
                                                    this.resizing = Some((
                                                        ResizeTarget::Inspector,
                                                        event.position.x,
                                                        inset,
                                                    ));
                                                    cx.stop_propagation();
                                                },
                                            ),
                                        )
                                        .on_click(cx.listener(
                                            |this, event: &ClickEvent, _, cx| {
                                                if event.click_count() == 2 {
                                                    this.inspector_width = None;
                                                    cx.notify();
                                                }
                                            },
                                        )),
                                ),
                        )
                    }),
            )
            .child(self.status_dock(inset, window, cx))
            .when(self.show_export_menu, |view| {
                view.child(self.export_menu(cx))
            })
            .when_some(self.path_menu.as_ref(), |view, (path, position)| {
                view.child(self.path_context_menu(path.clone(), *position, window, cx))
            })
            .into_any_element()
    }
}

fn surface(id: &'static str, active: bool, enabled: bool, ghost: bool) -> Stateful<Div> {
    let (background, hover) = match (ghost, active && enabled) {
        (false, true) => (rgb(ACCENT), rgb(ACCENT_HOVER)),
        (false, false) => (rgb(CONTROL), rgb(CONTROL_HOVER)),
        (true, true) => (rgba(0x0a84ff2e), rgba(0x0a84ff42)),
        (true, false) => (rgba(0), rgba(0xffffff14)),
    };
    div()
        .id(id)
        .h(px(30.))
        .rounded(px(7.))
        .flex()
        .items_center()
        .justify_center()
        .gap(px(6.))
        .flex_shrink_0()
        .whitespace_nowrap()
        .bg(background)
        .text_color(rgb(if !enabled {
            DISABLED
        } else if ghost && active {
            ACCENT_TEXT
        } else {
            TEXT
        }))
        .when(enabled, |button| {
            button.cursor_pointer().hover(move |style| style.bg(hover))
        })
        .when(!enabled, |button| {
            button
                .occlude()
                .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
        })
}

pub(super) fn button(
    id: &'static str,
    label: impl Into<SharedString>,
    active: bool,
    enabled: bool,
) -> Stateful<Div> {
    surface(id, active, enabled, false)
        .px_3()
        .child(label.into())
}

/// A borderless toolbar control; callers may append a label after the glyph.
pub(super) fn tool_button(
    id: &'static str,
    icon: &'static str,
    active: bool,
    enabled: bool,
) -> Stateful<Div> {
    surface(id, active, enabled, true)
        .min_w(px(30.))
        .px(px(7.))
        .child(crate::icons::glyph(
            icon,
            16.,
            if !enabled {
                DISABLED
            } else if active {
                ACCENT_TEXT
            } else {
                TEXT
            },
        ))
}

pub(super) fn spinner(id: impl Into<ElementId>, size: f32, color: u32) -> impl IntoElement {
    crate::icons::glyph("icons/spinner.svg", size, color).with_animation(
        id,
        Animation::new(Duration::from_millis(900)).repeat(),
        |svg, progress| svg.with_transformation(Transformation::rotate(percentage(progress))),
    )
}

struct Tooltip(SharedString);

impl Render for Tooltip {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        // Tooltips are separate roots and do not inherit the workspace text style.
        super::browser_view::glass()
            .px_2()
            .py_1()
            .rounded(px(6.))
            .font_family(UI_FONT)
            .text_size(px(11.))
            .text_color(rgb(TEXT))
            .child(self.0.clone())
    }
}

pub(super) fn tooltip(
    text: impl Into<SharedString>,
) -> impl Fn(&mut Window, &mut App) -> AnyView + 'static {
    let text = text.into();
    move |_, cx| cx.new(|_| Tooltip(text.clone())).into()
}

/// Formats a primary-modifier shortcut for the current platform.
pub(super) fn shortcut(key: &str) -> String {
    if cfg!(target_os = "macos") {
        format!("⌘{key}")
    } else {
        format!("Ctrl+{key}")
    }
}

pub(super) fn kind_label(kind: vnlens_core::ResourceKind) -> &'static str {
    use vnlens_core::ResourceKind;
    match kind {
        ResourceKind::Archive => "Archive",
        ResourceKind::Image => "Image",
        ResourceKind::Model => "3D model",
        ResourceKind::Audio => "Audio",
        ResourceKind::Script => "Script",
        ResourceKind::Data => "Data",
        ResourceKind::Font => "Font",
        ResourceKind::Video => "Video",
        ResourceKind::Unknown => "File",
    }
}

pub(super) fn bytes_label(size: u64) -> String {
    if size < 1024 {
        format!("{size} B")
    } else if size < 1024 * 1024 {
        format!("{:.1} KB", size as f64 / 1024.)
    } else if size < 1024 * 1024 * 1024 {
        format!("{:.1} MB", size as f64 / (1024. * 1024.))
    } else {
        format!("{:.1} GB", size as f64 / (1024. * 1024. * 1024.))
    }
}
