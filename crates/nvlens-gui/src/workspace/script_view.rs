//! Virtualized disassembly table with shared column widths and scroll offsets.

use std::cell::Cell;

use nvlens_script::ir::Script;

use super::*;

const HEADERS: [&str; 3] = ["Offset", "Opcode", "Operands"];
const FONT: &str = "Cascadia Mono";
const FONT_SIZE: f32 = 12.;
const CELL_PADDING: f32 = 10.;

pub(super) struct Table {
    rows: Vec<[SharedString; 3]>,
    widths: Cell<[Pixels; 3]>,
}

impl Table {
    pub(super) fn new(script: &Script, cancelled: &AtomicBool) -> nvlens_core::Result<Self> {
        if cancelled.load(Ordering::Relaxed) {
            return Err(nvlens_core::Error::Cancelled);
        }
        // Background preparation only formats data. WindowTextSystem's frame
        // cache must not be shared between worker tasks and window rendering.
        let rows = script
            .instructions
            .iter()
            .map(|instruction| {
                if cancelled.load(Ordering::Relaxed) {
                    return Err(nvlens_core::Error::Cancelled);
                }
                Ok([
                    format!("{:08X}", instruction.span.offset),
                    instruction.opcode_name(),
                    instruction.operands_disassembly(),
                ]
                .map(|text| -> SharedString {
                    // Keep every cell on one row without hiding control characters
                    // that can occur in engine-provided names and symbols.
                    text.chars()
                        .fold(String::new(), |mut text, ch| {
                            if ch.is_control() {
                                text.extend(ch.escape_default());
                            } else {
                                text.push(ch);
                            }
                            text
                        })
                        .into()
                }))
            })
            .collect::<nvlens_core::Result<_>>()?;
        Ok(Self {
            rows,
            widths: Cell::new([px(0.); HEADERS.len()]),
        })
    }
}

impl Workspace {
    pub(super) fn script_table(&self, table: &Table, cx: &mut Context<Self>) -> impl IntoElement {
        uniform_list(
            "script-ir",
            table.rows.len() + 1,
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
                        let cells = index.checked_sub(1).map_or_else(
                            || HEADERS.map(SharedString::from),
                            |index| table.rows[index].clone(),
                        );
                        (index, cells)
                    })
                    .collect();
                let style = TextStyle {
                    font_family: FONT.into(),
                    font_size: px(FONT_SIZE).into(),
                    ..TextStyle::default()
                };
                let mut widths = table.widths.get();
                for (_, cells) in &rows {
                    for (width, text) in widths.iter_mut().zip(cells) {
                        let run = style.to_run(text.len());
                        let measured = window
                            .text_system()
                            .shape_line(text.clone(), px(FONT_SIZE), &[run], None)
                            .width
                            .ceil()
                            + px(CELL_PADDING * 2. + 1.);
                        *width = (*width).max(measured);
                    }
                }
                if table.widths.replace(widths) != widths {
                    // Refresh the list's measured content width after a newly
                    // visible cell widens a column. Widths never shrink on scroll.
                    cx.notify();
                }
                let width = widths.iter().fold(px(0.), |total, width| total + *width);
                rows.into_iter()
                    .map(|(index, cells)| {
                        let instruction = index.checked_sub(1);
                        let selected = instruction.is_some() && this.ir_selected == instruction;
                        div()
                            .id(("ir-row", index))
                            .w(width)
                            .h(px(28.))
                            .flex()
                            .font_family(FONT)
                            .text_size(px(FONT_SIZE))
                            .whitespace_nowrap()
                            .border_b_1()
                            .border_color(rgb(BORDER))
                            .bg(rgb(if selected {
                                0x24496b
                            } else if instruction.is_none() {
                                BACKGROUND
                            } else if index.is_multiple_of(2) {
                                0x28282b
                            } else {
                                PANEL
                            }))
                            .when_some(instruction, |row, index| {
                                row.cursor_pointer()
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.ir_selected = Some(index);
                                        cx.notify();
                                    }))
                            })
                            .children(cells.into_iter().enumerate().map(|(column, text)| {
                                div()
                                    .w(widths[column])
                                    .h_full()
                                    .flex_shrink_0()
                                    .px(px(CELL_PADDING))
                                    .flex()
                                    .items_center()
                                    .when(column + 1 < HEADERS.len(), |cell| {
                                        cell.border_r_1().border_color(rgb(BORDER))
                                    })
                                    .text_color(rgb(
                                        if instruction.is_none() || (!selected && column == 0) {
                                            SECONDARY
                                        } else if !selected && column == 1 {
                                            0x9dcaff
                                        } else {
                                            0xf5f5f7
                                        },
                                    ))
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
        .min_h_0()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nvlens_script::ir::{Instruction, Opcode, Operand, Span, Value};
    use std::prelude::rust_2024::test;

    #[test]
    fn prepares_complete_cells_without_a_window_and_honors_cancellation() -> anyhow::Result<()> {
        let value = "Japanese 日本語\n\t".repeat(4096);
        let script = Script {
            ir_version: 2,
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
                    mnemonic: None,
                },
                operands: vec![Operand {
                    name: "value".into(),
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
        assert_eq!(table.rows[0][0].as_ref(), "100000020");
        assert_eq!(table.rows[0][1].as_ref(), "op_FF");
        assert_eq!(table.rows[0][2].as_ref(), format!("value={value:?}"));
        cancelled.store(true, Ordering::Relaxed);
        assert!(matches!(
            Table::new(&script, &cancelled),
            Err(nvlens_core::Error::Cancelled)
        ));
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
            assert_eq!(table.rows.len(), script.instructions.len());
            let name = entry.name.rsplit(['/', '\\']).next().unwrap_or("");
            if name == "yst00003.ybn" {
                checked_reported_script = true;
                println!(
                    "{name}: {} instructions, read/disassemble {read_time:?}, prepare {prepare_time:?}",
                    table.rows.len()
                );
            }
            if prepare_time > slowest.0 {
                slowest = (prepare_time, entry.name.clone());
            }
            records += table.rows.len();
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
