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
            .text_color(rgb(0xf5f5f7))
            .font_family("Segoe UI")
            .text_size(px(13.))
            .key_context("Workspace")
            .track_focus(&self.focus)
            .on_action(cx.listener(Self::toggle_settings))
            .on_action(cx.listener(Self::cancel))
            .child(
                div()
                    .h(px(52.))
                    .px_4()
                    .flex()
                    .items_center()
                    .border_b_1()
                    .border_color(rgb(BORDER))
                    .justify_end()
                    .child(
                        button("close-settings", "Close", false, true).on_click(cx.listener(
                            |this, _, window, cx| this.toggle_settings(&Settings, window, cx),
                        )),
                    ),
            )
            .child(
                div().p_4().child(
                    div().max_w(px(640.)).p_4().rounded(px(12.)).bg(rgb(PANEL))
                        .flex().items_center().gap_4()
                        .child(div().flex_1().min_w_0()
                            .child("Virtual script paths")
                            .child(div().mt_1().text_size(px(12.)).text_color(rgb(SECONDARY))
                                .child("Use original script folders and names instead of archive entry paths.")))
                        .child(div().text_size(px(12.)).text_color(rgb(SECONDARY))
                            .child(if enabled { "Virtual" } else { "Real" }))
                        .child(div().id("virtual-script-paths").relative().w(px(50.)).h(px(28.))
                            .flex_shrink_0().rounded_full().cursor_pointer()
                            .bg(rgb(if enabled { 0x34c759 } else { 0x48484a }))
                            .on_click(cx.listener(|this, _, _, cx| this.toggle_virtual_paths(cx)))
                            .child(div().absolute().left(px(3. + 22. * position)).top(px(3.))
                                .size(px(22.)).rounded_full().bg(rgb(0xffffff)).shadow_sm()))
                )
            )
            .child(self.status_dock(px(0.), window, cx))
            .with_animation(
                "settings-enter",
                Animation::new(Duration::from_millis(160)).with_easing(ease_in_out),
                |view, progress| view.opacity(progress),
            )
    }

    fn inspector(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let scroll = self.preview_scroll.0.borrow().base_handle.clone();
        let scrollable = self
            .preview
            .as_ref()
            .is_some_and(|preview| preview.image.is_none());
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

    fn preview_view(&self, cx: &mut Context<Self>) -> AnyElement {
        let Some(preview) = &self.preview else {
            return div().into_any_element();
        };
        if let Some(table) = &preview.ir_table {
            return self.script_table(table, cx).into_any_element();
        }
        if let Some(audio) = &preview.audio {
            return self.audio_view(audio, cx).into_any_element();
        }
        if preview.image.is_some() {
            return self.image_preview(cx);
        }
        let text = preview.lines.is_some();
        let count = if text {
            preview.lines.as_ref().map_or(0, Vec::len)
        } else {
            preview.bytes.len().div_ceil(12)
        };
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
                                let line = if text {
                                    preview
                                        .lines
                                        .as_ref()
                                        .and_then(|lines| lines.get(index))
                                        .and_then(|range| {
                                            std::str::from_utf8(&preview.bytes[range.clone()]).ok()
                                        })
                                        .unwrap_or("")
                                        .trim_end_matches(['\r', '\n'])
                                        .replace('\t', "    ")
                                } else {
                                    let start = index * 12;
                                    let bytes = &preview.bytes
                                        [start..(start + 12).min(preview.bytes.len())];
                                    format!(
                                        "{start:08X}  {}",
                                        bytes
                                            .iter()
                                            .map(|byte| format!("{byte:02X}"))
                                            .collect::<Vec<_>>()
                                            .join(" ")
                                    )
                                };
                                div()
                                    .h(px(22.))
                                    .font_family("Cascadia Mono")
                                    .text_size(px(11.))
                                    .whitespace_nowrap()
                                    .child(line)
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
        div()
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(BACKGROUND))
            .text_color(rgb(0xf5f5f7))
            .font_family("Segoe UI")
            .text_size(px(13.))
            .key_context("Workspace")
            .track_focus(&self.focus)
            .on_action(cx.listener(Self::open_dialog))
            .on_action(cx.listener(|this, _: &TogglePlayback, _, cx| {
                if this.show_inspector {
                    this.toggle_audio(cx);
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
            .child(self.toolbar(cx))
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
                            .child(self.browser(cx)),
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

pub(super) fn button(
    id: &'static str,
    label: impl Into<SharedString>,
    active: bool,
    enabled: bool,
) -> Stateful<Div> {
    div()
        .id(id)
        .h(px(30.))
        .px_3()
        .rounded_md()
        .flex()
        .items_center()
        .justify_center()
        .flex_shrink_0()
        .whitespace_nowrap()
        .bg(rgb(if active && enabled { ACCENT } else { 0x363639 }))
        .text_color(rgb(if enabled { 0xf5f5f7 } else { 0x77777c }))
        .when(enabled, |button| {
            button
                .cursor_pointer()
                .hover(|style| style.bg(rgb(if active { 0x409cff } else { 0x46464b })))
        })
        .when(!enabled, |button| {
            button
                .occlude()
                .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
        })
        .child(label.into())
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
