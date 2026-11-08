//! Virtualized script tables with shared column widths and scroll offsets.

use std::cell::Cell;

use nvlens_script::ir::Script;

use super::*;

const FONT: &str = "Cascadia Mono";
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
                                            0x9dcaff
                                        } else {
                                            0xf5f5f7
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
                                                        .hover(|style| style.bg(rgb(0x37373b)))
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
                            .text_color(rgb(0x9dcaff))
                            .block_mouse_except_scroll()
                            .cursor_pointer()
                            .hover(|style| style.bg(rgb(0x37373b)))
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
mod tests {
    use super::*;
    use nvlens_script::ir::{Arg, Instruction, Opcode, Span, Value};
    use std::prelude::rust_2024::test;

    #[test]
    fn prepares_complete_cells_without_a_window_and_honors_cancellation() -> anyhow::Result<()> {
        let value = "Japanese 日本語\n\t".repeat(4096);
        let script = Script {
            ir_version: nvlens_script::ir::VERSION,
            format: "test".into(),
            format_version: 1,
            sections: Vec::new(),
            instructions: vec![Instruction {
                id: 0,
                span: Span {
                    offset: 0x1_0000_0020,
                    size: 4,
                },
                source_line: Some(3),
                opcode: Opcode {
                    namespace: "test".into(),
                    code: 255,
                    operation: nvlens_script::ir::Operation::Unknown,
                    variant: None,
                    native_mnemonic: None,
                },
                args: vec![Arg {
                    native_name: None,
                    name: nvlens_script::ir::ArgName::Value,
                    span: Span {
                        offset: 36,
                        size: 0,
                    },
                    value: Value::Text(value.clone()),
                    attributes: Vec::new(),
                }],
                attributes: Vec::new(),
            }],
        };
        let cancelled = AtomicBool::new(false);
        let table = Table::new(&script, &cancelled)?;
        assert_eq!(table.rows[0].cells[0].as_ref(), "100000020");
        assert_eq!(table.rows[0].cells[1].as_ref(), "unknown");
        assert_eq!(
            table.rows[0].cells[2].as_ref(),
            format!("native=test:0xFF, value={value:?}")
        );
        cancelled.store(true, Ordering::Relaxed);
        assert!(matches!(
            Table::new(&script, &cancelled),
            Err(nvlens_core::Error::Cancelled)
        ));
        Ok(())
    }

    /// NVLENS_PSB_GAME=<game> cargo test -p nvlens-gui validates_psb_scenario_preview -- --ignored --nocapture
    #[test]
    #[ignore = "Requires NVLENS_PSB_GAME with data.xp3; reads PSB scenario previews without a window"]
    fn validates_psb_scenario_preview() -> anyhow::Result<()> {
        nvlens_archive::init();
        nvlens_script::init();
        let root = PathBuf::from(
            std::env::var_os("NVLENS_PSB_GAME")
                .ok_or_else(|| anyhow::anyhow!("Set NVLENS_PSB_GAME"))?,
        );
        let cancel = AtomicBool::new(false);
        let game = Arc::new(
            nvlens_engine::identify(&root, &cancel)?
                .ok_or_else(|| anyhow::anyhow!("Engine not identified"))?,
        );
        let path = root.join("data.xp3");
        let route = game
            .route_path(&path)
            .ok_or_else(|| anyhow::anyhow!("No archive route"))?;
        let mut recovery =
            nvlens_archive::krkr::NameRecovery::open(&[(path.clone(), route.options)], &cancel)?;
        while recovery.step(&cancel)? {}
        assert_eq!(recovery.progress().failed, 0);
        let mut checked = 0;
        let mut rows = 0;
        for (_, names) in recovery.paths() {
            let archive = Arc::new(
                crate::archive::MountedArchive::open(path.clone(), false, game.clone())?
                    .ok_or_else(|| anyhow::anyhow!("Archive not recognized"))?
                    .with_paths(names)?,
            );
            for (index, name) in archive.paths.iter().enumerate() {
                if !name.ends_with(".ks.scn") {
                    continue;
                }
                let resource = crate::resource::read(
                    &Target::Entry {
                        archive: archive.clone(),
                        index,
                    },
                    false,
                    &cancel,
                )?;
                assert!(resource.psb.is_some(), "{name}");
                assert!(resource.script.is_none(), "{name}");
                let mut preview = Preview::new(resource, &cancel)?;
                assert!(preview.lines.is_none(), "{name}");
                let psb = preview
                    .psb
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing PSB tree"))?;
                let table = preview
                    .ir_table
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("Missing PSB table"))?;
                assert_eq!(table.psb_json(0, psb).transpose()?, Some(psb.to_json()?));
                let scenes = table
                    .visible
                    .iter()
                    .copied()
                    .find(|&row| table.rows[row].cells[1].as_ref() == "scenes")
                    .ok_or_else(|| anyhow::anyhow!("Missing scenes field in {name}"))?;
                assert!(table.expandable(scenes), "{name}");
                assert!(!table.rows[scenes].expanded);
                let visible = table.visible.clone();
                table.toggle(scenes, None);
                assert!(table.visible.len() > visible.len());
                table.toggle(scenes, None);
                assert_eq!(table.visible, visible);
                rows += table.rows.len();
                checked += 1;
            }
        }
        assert!(checked > 0);
        println!(
            "Validated {checked} PSB scenario previews with {rows} tree rows without a window"
        );
        Ok(())
    }

    /// NVLENS_ESCUDE_GAME=<game> cargo test -p nvlens-gui validates_escude_preview_data -- --ignored --nocapture
    #[test]
    #[ignore = "Requires NVLENS_ESCUDE_GAME; validates source text, structured rows and navigation without a window"]
    fn validates_escude_preview_data() -> anyhow::Result<()> {
        nvlens_archive::init();
        nvlens_script::init();
        let root = PathBuf::from(
            std::env::var_os("NVLENS_ESCUDE_GAME")
                .ok_or_else(|| anyhow::anyhow!("Set NVLENS_ESCUDE_GAME"))?,
        );
        let cancel = AtomicBool::new(false);
        let game = Arc::new(
            nvlens_engine::identify(&root, &cancel)?
                .ok_or_else(|| anyhow::anyhow!("Engine not identified"))?,
        );
        let mut sources = 0;
        let mut structures = 0;
        for file in [
            "haison2_fd.bin",
            "script.bin",
            "data.bin",
            "gfx.bin",
            "snd.bin",
        ] {
            let archive = Arc::new(
                crate::archive::MountedArchive::open(root.join(file), false, game.clone())?
                    .ok_or_else(|| anyhow::anyhow!("Archive not recognized"))?,
            );
            for (index, entry) in archive.entries.iter().enumerate() {
                if entry.kind != nvlens_core::ResourceKind::Script {
                    continue;
                }
                let target = Target::Entry {
                    archive: archive.clone(),
                    index,
                };
                assert!(!target.archive_hint(), "{}", entry.name);
                assert!(crate::browser::open(&target, &cancel, false)?.is_none());
                let resource = crate::resource::read(&target, false, &cancel)?;
                let raw_resource = crate::resource::read(&target, true, &cancel)?;
                assert!(raw_resource.script.is_none());
                assert!(raw_resource.bytes.starts_with(b"acp\0"));
                let mut preview = Preview::new(resource, &cancel)?;
                if file == "haison2_fd.bin" || entry.name == "credit.txt" {
                    assert!(preview.script.is_none());
                    assert!(preview.ir_table.is_none());
                    assert!(preview.lines.is_some());
                    let original = target.read(false, &cancel)?;
                    let expected = nvlens_script::decode_text_as("text/escude", &original)?
                        .ok_or_else(|| anyhow::anyhow!("No source text"))?;
                    assert_eq!(std::str::from_utf8(&preview.bytes)?, expected);
                    sources += 1;
                } else {
                    let script = preview
                        .script
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("No structure for {}", entry.name))?;
                    if script.format == "scenario/escude" {
                        for instruction in &script.instructions {
                            if instruction.opcode.namespace == "escude.scenario"
                                && instruction.opcode.code == 44
                            {
                                assert!(
                                    instruction
                                        .opcode
                                        .native_mnemonic
                                        .as_deref()
                                        .is_some_and(|s| s.starts_with("proc_"))
                                );
                            }
                        }
                    }
                    let table = preview
                        .ir_table
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("Missing preview table"))?;
                    assert!(preview.lines.is_none());
                    let visible = table.visible.clone();
                    assert_eq!(visible.len(), script.instructions.len());
                    if let Some(&row) = visible.iter().find(|&&row| table.expandable(row)) {
                        table.toggle(row, None);
                        assert!(table.visible.len() > visible.len());
                        table.toggle(row, None);
                        assert_eq!(table.visible, visible);
                    }
                    let exported = crate::resource::convert(
                        &preview.bytes,
                        crate::resource::ExportKind::Ir,
                        Some(script),
                        0,
                    )?;
                    assert_eq!(exported, script.to_json()?);
                    structures += 1;
                }
            }
        }
        assert_eq!(sources, 119);
        assert_eq!(structures, 201);
        println!(
            "Validated {sources} text previews (118 pseudo-C sources) and {structures} structured previews without a window"
        );
        Ok(())
    }

    /// NVLENS_SYSTEMNNN_GAME=<game> cargo test -p nvlens-gui validates_systemnnn_record_preview -- --ignored --nocapture
    #[test]
    #[ignore = "Requires NVLENS_SYSTEMNNN_GAME; prepares and expands script rows without a window"]
    fn validates_systemnnn_record_preview() -> anyhow::Result<()> {
        nvlens_script::init();
        let root = PathBuf::from(
            std::env::var_os("NVLENS_SYSTEMNNN_GAME")
                .ok_or_else(|| anyhow::anyhow!("Set NVLENS_SYSTEMNNN_GAME"))?,
        )
        .join("spt");
        let cancelled = AtomicBool::new(false);
        let mut total = 0;
        let start = Instant::now();
        for name in [
            "BCmkri_backscript.spt",
            "etc.spt",
            "s100.spt",
            "s200.spt",
            "s300.spt",
            "s400.spt",
            "sys.spt",
        ] {
            let bytes = std::fs::read(root.join(name))?;
            let script = nvlens_script::disassemble_as("spt/systemnnn", &bytes, None)?
                .ok_or_else(|| anyhow::anyhow!("SPT not recognized"))?;
            let mut table = Table::new(&script, &cancelled)?;
            let roots = table.visible.clone();
            assert_eq!(roots.len(), script.instructions.len());
            for (instruction, &row) in roots.iter().enumerate() {
                assert_eq!(table.instruction_index(row), Some(instruction));
                if script.instructions[instruction].opcode.variant
                    == Some(nvlens_script::ir::Qualifier::ResourceTable)
                {
                    assert!(!table.rows[row].cells[2].contains("hex["));
                    table.toggle(row, None);
                    assert!(table.visible.len() >= roots.len());
                    let strings: Vec<_> = table.rows[row + 1..table.rows[row].end]
                        .iter()
                        .filter(|row| row.cells[1].starts_with("string["))
                        .collect();
                    assert!(!strings.is_empty());
                    assert!(strings.iter().all(|row| row.cells[2].starts_with("{text:")));
                    table.toggle(row, None);
                    assert_eq!(table.visible, roots);
                }
            }
            total += roots.len();
        }
        assert_eq!(total, 101_511);
        println!(
            "Prepared and expanded {total} SPT instructions in {:?}",
            start.elapsed()
        );
        Ok(())
    }

    /// NVLENS_YURIS_GAME=<game> cargo test -p nvlens-gui validates_game_script_tables -- --ignored --nocapture
    #[test]
    #[ignore = "Requires NVLENS_YURIS_GAME; prepares every script preview without a window"]
    fn validates_game_script_tables() -> anyhow::Result<()> {
        nvlens_archive::init();
        nvlens_script::init();
        let root = PathBuf::from(
            std::env::var_os("NVLENS_YURIS_GAME")
                .ok_or_else(|| anyhow::anyhow!("Set NVLENS_YURIS_GAME"))?,
        );
        let archive = Arc::new(
            crate::archive::MountedArchive::open(
                root.join("pac/Scripts.ypf"),
                false,
                Arc::new(
                    nvlens_engine::identify(&root, &AtomicBool::new(false))?
                        .ok_or_else(|| anyhow::anyhow!("Engine not identified"))?,
                ),
            )?
            .ok_or_else(|| anyhow::anyhow!("Archive not recognized"))?,
        );
        let cancelled = AtomicBool::new(false);
        let start = Instant::now();
        let mut checked = 0;
        let mut records = 0;
        let mut checked_reported_script = false;
        let mut slowest = (Duration::ZERO, String::new());
        for (index, entry) in archive.entries.iter().enumerate() {
            let read_start = Instant::now();
            let resource = crate::resource::read(
                &Target::Entry {
                    archive: archive.clone(),
                    index,
                },
                false,
                &cancelled,
            )?;
            let read_time = read_start.elapsed();
            let prepare_start = Instant::now();
            let preview = Preview::new(resource, &cancelled)?;
            let prepare_time = prepare_start.elapsed();
            let script = preview
                .script
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Script not recognized"))?;
            let table = preview
                .ir_table
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Table not prepared"))?;
            assert_eq!(table.visible.len(), script.instructions.len());
            let name = entry.name.rsplit(['/', '\\']).next().unwrap_or("");
            if name == "yst00003.ybn" {
                checked_reported_script = true;
                println!(
                    "{name}: {} instructions, read/disassemble {read_time:?}, prepare {prepare_time:?}",
                    table.visible.len()
                );
            }
            if prepare_time > slowest.0 {
                slowest = (prepare_time, entry.name.clone());
            }
            records += table.visible.len();
            checked += 1;
        }
        assert!(checked_reported_script);
        println!(
            "Prepared {checked} script previews ({records} records) in {:?}; slowest preparation {:?} ({})",
            start.elapsed(),
            slowest.0,
            slowest.1
        );
        Ok(())
    }
}
