//! Virtualized script tables with shared column widths and scroll offsets.

use std::cell::Cell;

use vnlens_script::ir::Script;

use super::*;

const FONT: &str = MONO_FONT;
const FONT_SIZE: f32 = 12.;
const CELL_PADDING: f32 = 10.;

mod table;
pub(super) use table::Table;

const ROW_HEIGHT: f32 = 28.;
const INDENT: f32 = 14.;
const DISCLOSURE: f32 = 18.;

impl Workspace {
    fn toggle_record(&mut self, row: usize, cx: &mut Context<Self>) {
        let Some(table) = self
            .preview
            .as_mut()
            .and_then(|preview| preview.ir_table.as_mut())
        else {
            return;
        };
        let scroll = self.preview_scroll.0.borrow().base_handle.clone();
        let position = table.visible.binary_search(&row).ok();
        let depth = table.rows[row].depth;
        let collapsing = table.rows[row].expanded && table.expandable(row);
        self.ir_selected = table.toggle(row, self.ir_selected);
        // A pinned header can collapse thousands of rows above the viewport.
        // Keep that row visible beneath its ancestors and preserve X offset.
        if collapsing
            && let Some(position) = position
            && px((position + 1) as f32 * ROW_HEIGHT)
                < -scroll.offset().y + px(depth as f32 * ROW_HEIGHT)
        {
            self.preview_scroll.scroll_to_item_strict_with_offset(
                position + 1,
                ScrollStrategy::Top,
                depth,
            );
        }
        cx.notify();
    }

    pub(super) fn script_table(&self, table: &Table, cx: &mut Context<Self>) -> impl IntoElement {
        let list = uniform_list(
            "script-ir",
            table.visible.len() + 1,
            cx.processor(move |this, range: Range<usize>, window, cx| {
                let Some(table) = this
                    .preview
                    .as_ref()
                    .and_then(|preview| preview.ir_table.as_ref())
                else {
                    return Vec::new();
                };
                // UniformList requests its header for measurement and the visible
                // rows for rendering. Shape only those cells on the UI thread.
                let rows: Vec<_> = range
                    .map(|index| {
                        let row = index.checked_sub(1).map(|index| table.visible[index]);
                        let cells = row.map_or_else(
                            || table.headers.map(SharedString::from),
                            |row| table.rows[row].cells.clone(),
                        );
                        (index, row, cells)
                    })
                    .collect();
                let style = TextStyle {
                    font_family: FONT.into(),
                    font_size: px(FONT_SIZE).into(),
                    ..TextStyle::default()
                };
                let mut widths = table.widths.get();
                for (_, row, cells) in &rows {
                    for (column, (width, text)) in widths.iter_mut().zip(cells).enumerate() {
                        let run = style.to_run(text.len());
                        let measured = window
                            .text_system()
                            .shape_line(text.clone(), px(FONT_SIZE), &[run], None)
                            .width
                            .ceil()
                            + px(CELL_PADDING * 2. + 1.);
                        let inset = if column == 1 {
                            px(DISCLOSURE
                                + row.map_or(0., |row| table.rows[row].depth as f32 * INDENT))
                        } else {
                            px(0.)
                        };
                        *width = (*width).max(measured + inset);
                    }
                }
                if table.widths.replace(widths) != widths {
                    // Refresh the list's measured content width after a newly
                    // visible cell widens a column. Widths never shrink on scroll.
                    cx.notify();
                }
                let width = widths.iter().fold(px(0.), |total, width| total + *width);
                rows.into_iter()
                    .map(|(index, node, cells)| {
                        let selected = node.is_some() && this.ir_selected == node;
                        let depth = node.map_or(0, |node| table.rows[node].depth);
                        let expandable = node.is_some_and(|node| table.expandable(node));
                        let expanded = node.is_some_and(|node| table.rows[node].expanded);
                        div()
                            .id(("ir-row", node.map_or(0, |node| node + 1)))
                            .w(width)
                            .h(px(ROW_HEIGHT))
                            .flex()
                            .font_family(FONT)
                            .text_size(px(FONT_SIZE))
                            .whitespace_nowrap()
                            .border_b_1()
                            .border_color(rgb(BORDER))
                            .bg(rgb(if selected {
                                0x24496b
                            } else if node.is_none() {
                                BACKGROUND
                            } else if index.is_multiple_of(2) {
                                0x28282b
                            } else {
                                PANEL
                            }))
                            .when_some(node, |row, index| {
                                row.cursor_pointer().on_click(cx.listener(
                                    move |this, event: &ClickEvent, _, cx| {
                                        this.ir_selected = Some(index);
                                        if event.click_count() == 2 {
                                            this.toggle_record(index, cx);
                                        }
                                        cx.notify();
                                    },
                                ))
                            })
                            .children(cells.into_iter().enumerate().map(|(column, text)| {
                                div()
                                    .w(widths[column])
                                    .h_full()
                                    .flex_shrink_0()
                                    .px(px(CELL_PADDING))
                                    .flex()
                                    .items_center()
                                    .when(column + 1 < table.headers.len(), |cell| {
                                        cell.border_r_1().border_color(rgb(BORDER))
                                    })
                                    .text_color(rgb(
                                        if node.is_none() || (!selected && column == 0) {
                                            SECONDARY
                                        } else if !selected && column == 1 {
                                            ACCENT_TEXT
                                        } else {
                                            TEXT
                                        },
                                    ))
                                    .when(column == 1, |cell| {
                                        cell.child(
                                            div().w(px(depth as f32 * INDENT)).flex_shrink_0(),
                                        )
                                        .child(
                                            div()
                                                .id((
                                                    "ir-disclosure",
                                                    node.map_or(0, |node| node + 1),
                                                ))
                                                .w(px(DISCLOSURE))
                                                .h_full()
                                                .flex_shrink_0()
                                                .flex()
                                                .items_center()
                                                .justify_center()
                                                .when(expandable, |button| {
                                                    button
                                                        .cursor_pointer()
                                                        .hover(|style| style.bg(rgb(BORDER)))
                                                        .on_click(cx.listener(
                                                            move |this, _, _, cx| {
                                                                cx.stop_propagation();
                                                                if let Some(node) = node {
                                                                    this.toggle_record(node, cx);
                                                                }
                                                            },
                                                        ))
                                                        .child(if expanded { "▾" } else { "▸" })
                                                }),
                                        )
                                    })
                                    .child(text)
                            }))
                    })
                    .collect()
            }),
        )
        // The header shares the row geometry, so even an empty script has
        // measurable columns and horizontal scrolling stays aligned.
        .with_width_from_item(Some(0))
        .with_horizontal_sizing_behavior(ListHorizontalSizingBehavior::Unconstrained)
        .track_scroll(self.preview_scroll.clone())
        .flex_1()
        .min_h_0();
        div()
            .relative()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .min_w_0()
            .overflow_hidden()
            .child(list)
            .child(self.sticky_records(cx))
    }

    fn sticky_records(&self, cx: &mut Context<Self>) -> impl IntoElement {
        canvas(
            cx.processor(|this, bounds: Bounds<Pixels>, window, cx| {
                // Runs after UniformList prepaint, using its current clamped
                // offset and widths for wheel, scrollbar and resize changes.
                let scroll = this.preview_scroll.0.borrow().base_handle.clone();
                let first = (-scroll.offset().y / px(ROW_HEIGHT)).floor().max(0.) as usize;
                let table = this.preview.as_ref()?.ir_table.as_ref()?;
                let pinned = table.sticky_rows(first);
                if pinned.is_empty() {
                    return None;
                }
                let mut headers = div()
                    .id("ir-sticky-records")
                    .w_full()
                    .flex()
                    .flex_col()
                    .overflow_hidden()
                    .children(pinned.into_iter().map(|row| {
                        let item = &table.rows[row];
                        // The collapse control stays visible even when the
                        // table is scrolled horizontally through long values.
                        div()
                            .id(("ir-sticky-record", row))
                            .h(px(ROW_HEIGHT))
                            .flex_shrink_0()
                            .w_full()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .px(px(CELL_PADDING))
                            .font_family(FONT)
                            .text_size(px(FONT_SIZE))
                            .whitespace_nowrap()
                            .overflow_hidden()
                            .bg(rgb(PANEL))
                            .border_b_1()
                            .border_color(rgb(BORDER))
                            .text_color(rgb(ACCENT_TEXT))
                            .block_mouse_except_scroll()
                            .cursor_pointer()
                            .hover(|style| style.bg(rgb(BORDER)))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                cx.stop_propagation();
                                this.toggle_record(row, cx);
                            }))
                            .child("▾")
                            .child(item.cells[1].clone())
                            .child(
                                div()
                                    .text_color(rgb(SECONDARY))
                                    .child(item.cells[2].clone()),
                            )
                    }))
                    .into_any_element();
                window.with_content_mask(Some(ContentMask { bounds }), |window| {
                    headers.prepaint_as_root(
                        bounds.origin,
                        size(
                            AvailableSpace::Definite(bounds.size.width),
                            AvailableSpace::MinContent,
                        ),
                        window,
                        cx,
                    );
                });
                Some(headers)
            }),
            |bounds, headers, window, cx| {
                if let Some(mut headers) = headers {
                    window.with_content_mask(Some(ContentMask { bounds }), |window| {
                        headers.paint(window, cx)
                    });
                }
            },
        )
        .absolute()
        .inset_0()
    }
}

#[cfg(test)]
#[path = "../../tests/workspace/script_view.rs"]
mod tests;
