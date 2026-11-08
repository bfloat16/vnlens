//! Window-independent row preparation and expansion state for script previews.
//! Preorder rows keep stable IDs; a visible index skips collapsed subtrees.
//! All text preparation runs in the existing background preview task.
use super::*;
use nvlens_script::ir::{Arg, DataOperation, Operation, Value};
use std::fmt::Write;

mod psb;

// Display wrapping only; raw bytes and export retain their original lengths.
const BYTES_PER_ROW: usize = 32;

pub(super) enum Source {
    Instruction(usize),
    Root,
    Property(String),
    Index(usize),
}

pub(super) struct Row {
    pub(super) cells: [SharedString; 3],
    pub(super) depth: usize,
    pub(super) end: usize,
    pub(super) expanded: bool,
    source: Source,
    parent: Option<usize>,
}

pub(crate) struct Table {
    pub(super) headers: &'static [&'static str; 3],
    pub(super) rows: Vec<Row>,
    pub(super) visible: Vec<usize>,
    pub(super) widths: Cell<[Pixels; 3]>,
}

impl Table {
    pub(crate) fn new(script: &Script, cancelled: &AtomicBool) -> nvlens_core::Result<Self> {
        let mut table = Self {
            headers: &["Offset", "Opcode / Field", "Operands"],
            rows: Vec::new(),
            visible: Vec::new(),
            widths: Cell::new([px(0.); 3]),
        };
        if cancelled.load(Ordering::Relaxed) {
            return Err(nvlens_core::Error::Cancelled);
        }
        for (instruction_index, instruction) in script.instructions.iter().enumerate() {
            if cancelled.load(Ordering::Relaxed) {
                return Err(nvlens_core::Error::Cancelled);
            }
            let record = instruction.opcode.operation == Operation::Data(DataOperation::Record);
            let root = table.rows.len();
            table.visible.push(root);
            let args = if record {
                let mut summary = String::new();
                if let Some(variant) = instruction.opcode.variant {
                    let _ = write!(summary, "{}, ", variant.name());
                }
                let _ = write!(
                    summary,
                    "{} fields, {} bytes",
                    instruction.args.len(),
                    instruction.span.size
                );
                for arg in &instruction.args {
                    match &arg.value {
                        Value::Group(fields) => {
                            let _ = write!(summary, ", {}: {} items", arg.name, fields.len());
                        }
                        Value::Bytes(bytes) => {
                            let _ = write!(summary, ", {}: {} bytes", arg.name, bytes.len());
                        }
                        _ => {}
                    }
                }
                summary
            } else {
                instruction.args_disassembly()
            };
            table.push(
                Source::Instruction(instruction_index),
                None,
                [
                    format!("{:08X}", instruction.span.offset),
                    instruction.opcode_name(),
                    args,
                ],
            );
            if record {
                table.record_rows(instruction_index, root, &instruction.args, cancelled)?;
            }
            table.rows[root].end = table.rows.len();
        }
        Ok(table)
    }

    fn push(&mut self, source: Source, parent: Option<usize>, cells: [String; 3]) -> usize {
        let index = self.rows.len();
        let depth = parent.map_or(0, |parent| self.rows[parent].depth + 1);
        self.rows.push(Row {
            cells: cells.map(cell),
            source,
            parent,
            depth,
            end: index + 1,
            expanded: depth != 0,
        });
        index
    }

    fn record_rows(
        &mut self,
        instruction: usize,
        root: usize,
        args: &[Arg],
        cancelled: &AtomicBool,
    ) -> nvlens_core::Result<()> {
        // Explicit traversal avoids a nesting limit and recursive row building.
        enum Pending<'a> {
            Field(&'a Arg, usize),
            End(usize),
        }
        let mut pending: Vec<_> = args
            .iter()
            .rev()
            .map(|arg| Pending::Field(arg, root))
            .collect();
        while let Some(item) = pending.pop() {
            if cancelled.load(Ordering::Relaxed) {
                return Err(nvlens_core::Error::Cancelled);
            }
            let (arg, parent) = match item {
                Pending::Field(arg, parent) => (arg, parent),
                Pending::End(index) => {
                    self.rows[index].end = self.rows.len();
                    continue;
                }
            };
            let name = arg.name.to_string();
            match &arg.value {
                // A tuple is one record row; a collection or nested group
                // exposes each child separately. Indexed tuple members such
                // as string terminators do not turn a tuple into a table.
                Value::Group(fields)
                    if fields.iter().any(|field| !inline(&field.value))
                        || (arg.name.index().is_none()
                            && fields.iter().any(|field| field.name.index().is_some())) =>
                {
                    let row = self.push(
                        Source::Instruction(instruction),
                        Some(parent),
                        [
                            format!("{:08X}", arg.span.offset),
                            name,
                            format!("{} items", fields.len()),
                        ],
                    );
                    pending.push(Pending::End(row));
                    pending.extend(fields.iter().rev().map(|arg| Pending::Field(arg, row)));
                }
                Value::Bytes(bytes) if bytes.len() > BYTES_PER_ROW => {
                    let row = self.push(
                        Source::Instruction(instruction),
                        Some(parent),
                        [
                            format!("{:08X}", arg.span.offset),
                            name,
                            format!("{} bytes", bytes.len()),
                        ],
                    );
                    for (chunk, bytes) in bytes.chunks(BYTES_PER_ROW).enumerate() {
                        if cancelled.load(Ordering::Relaxed) {
                            return Err(nvlens_core::Error::Cancelled);
                        }
                        let start = chunk * BYTES_PER_ROW;
                        let mut text = String::new();
                        for (index, byte) in bytes.iter().enumerate() {
                            if index != 0 {
                                text.push(' ');
                            }
                            let _ = write!(text, "{byte:02X}");
                        }
                        self.push(
                            Source::Instruction(instruction),
                            Some(row),
                            [
                                format!("{:08X}", arg.span.offset + start as u64),
                                format!("bytes[{start}..{}]", start + bytes.len()),
                                text,
                            ],
                        );
                    }
                    self.rows[row].end = self.rows.len();
                }
                _ => {
                    self.push(
                        Source::Instruction(instruction),
                        Some(parent),
                        [
                            format!("{:08X}", arg.span.offset),
                            name,
                            arg.value.disassembly(),
                        ],
                    );
                }
            }
        }
        Ok(())
    }

    pub(super) fn expandable(&self, index: usize) -> bool {
        self.rows[index].end > index + 1
    }

    /// Expanded ancestors at the viewport's top, including headers directly
    /// under the pinned stack. `first_item` includes the list's column header.
    pub(super) fn sticky_rows(&self, first_item: usize) -> Vec<usize> {
        let Some(&row) = first_item
            .checked_sub(1)
            .and_then(|index| self.visible.get(index))
        else {
            return Vec::new();
        };
        let mut pinned = Vec::new();
        let mut ancestor = Some(row);
        while let Some(row) = ancestor {
            if self.rows[row].expanded && self.expandable(row) {
                pinned.push(row);
            }
            ancestor = self.rows[row].parent;
        }
        pinned.reverse();
        while let Some(&parent) = pinned.last() {
            let Some(&next) = self.visible.get(first_item + pinned.len() - 1) else {
                break;
            };
            if self.rows[next].parent != Some(parent)
                || !self.rows[next].expanded
                || !self.expandable(next)
            {
                break;
            }
            pinned.push(next);
        }
        pinned
    }

    /// Returns the collapsed parent's stable row ID when it hides selection.
    pub(super) fn toggle(&mut self, index: usize, selected: Option<usize>) -> Option<usize> {
        if !self.expandable(index) {
            return selected;
        }
        let Some(position) = self.visible.iter().position(|&row| row == index) else {
            return selected;
        };
        let end = self.rows[index].end;
        let expanded = !self.rows[index].expanded;
        self.rows[index].expanded = expanded;
        if expanded {
            let mut children = Vec::new();
            let mut child = index + 1;
            while child < end {
                children.push(child);
                child = if self.rows[child].expanded {
                    child + 1
                } else {
                    self.rows[child].end
                };
            }
            self.visible.splice(position + 1..position + 1, children);
        } else {
            let count = self.visible[position + 1..].partition_point(|&row| row < end);
            self.visible.drain(position + 1..position + 1 + count);
        }
        if !expanded && selected.is_some_and(|row| index < row && row < end) {
            Some(index)
        } else {
            selected
        }
    }

    pub(crate) fn instruction_index(&self, row: usize) -> Option<usize> {
        match &self.rows.get(row)?.source {
            Source::Instruction(index) => Some(*index),
            _ => None,
        }
    }
}

fn inline(value: &Value) -> bool {
    match value {
        Value::Group(_) => false,
        Value::Bytes(bytes) => bytes.len() <= BYTES_PER_ROW,
        _ => true,
    }
}

fn cell(text: String) -> SharedString {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use nvlens_script::ir::{ArgName as A, Instruction, Opcode, Qualifier, Span};
    use std::prelude::rust_2024::test;

    fn arg(name: A, offset: u64, value: Value) -> Arg {
        Arg {
            name,
            native_name: None,
            span: Span { offset, size: 4 },
            value,
            attributes: Vec::new(),
        }
    }
    fn script(args: Vec<Arg>) -> Script {
        Script {
            ir_version: nvlens_script::ir::VERSION,
            format: "test".into(),
            format_version: 0,
            sections: Vec::new(),
            instructions: vec![
                Instruction {
                    id: 70,
                    span: Span {
                        offset: 0,
                        size: 64,
                    },
                    source_line: None,
                    opcode: Opcode {
                        operation: Operation::Data(DataOperation::Record),
                        variant: Some(Qualifier::ResourceTable),
                        namespace: "test".into(),
                        code: 1,
                        native_mnemonic: None,
                    },
                    args,
                    attributes: Vec::new(),
                },
                Instruction {
                    id: 90,
                    span: Span {
                        offset: 64,
                        size: 4,
                    },
                    source_line: None,
                    opcode: Opcode {
                        operation: Operation::Unknown,
                        variant: None,
                        namespace: "test".into(),
                        code: 2,
                        native_mnemonic: None,
                    },
                    args: Vec::new(),
                    attributes: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn records_start_collapsed_and_expand_each_tuple_as_one_complete_row() -> anyhow::Result<()> {
        let text = "日本語\n\t".repeat(1000);
        let script = script(vec![arg(
            A::StringPool,
            16,
            Value::Group(vec![
                arg(
                    A::StringAt(0),
                    16,
                    Value::Group(vec![
                        arg(A::Text, 16, Value::Text(text.clone())),
                        arg(A::Terminator(0), 20, Value::Unsigned(0)),
                    ]),
                ),
                arg(
                    A::StringAt(1),
                    24,
                    Value::Group(vec![
                        arg(A::Text, 24, Value::Text(String::new())),
                        arg(A::Terminator(0), 28, Value::Unsigned(0)),
                    ]),
                ),
            ]),
        )]);
        let exported = script.to_json()?;
        let mut table = Table::new(&script, &AtomicBool::new(false))?;
        assert_eq!(table.visible, [0, 4]);
        assert_eq!(
            table.rows[0].cells[2].as_ref(),
            "resource_table, 1 fields, 64 bytes, string_pool: 2 items"
        );
        assert!(!table.rows[0].cells[2].contains("日本語"));
        table.toggle(0, None);
        assert_eq!(table.visible, [0, 1, 2, 3, 4]);
        assert_eq!(table.rows[1].cells[2].as_ref(), "2 items");
        assert!(!table.expandable(2));
        assert_eq!(table.rows[2].cells[1].as_ref(), "string[0]");
        assert_eq!(
            table.rows[2].cells[2].as_ref(),
            format!("{{text:{text:?}, terminator[0]:0x0}}")
        );
        assert!(table.rows[3].cells[2].contains("text:\"\""));
        assert_eq!(table.instruction_index(2), Some(0));
        assert_eq!(table.instruction_index(4), Some(1));
        assert_eq!(script.to_json()?, exported);
        Ok(())
    }

    #[test]
    fn nested_collapse_preserves_other_rows_selection_and_expansion_state() -> anyhow::Result<()> {
        let script = script(vec![arg(
            A::Resources,
            8,
            Value::Group(vec![
                arg(A::ValueAt(0), 8, Value::DataAddress(100)),
                arg(A::ValueAt(1), 12, Value::DataAddress(104)),
            ]),
        )]);
        let mut table = Table::new(&script, &AtomicBool::new(false))?;
        table.toggle(0, None);
        table.widths.set([px(100.); 3]);
        let selected = table.toggle(1, Some(3));
        assert_eq!(selected, Some(1));
        assert_eq!(table.visible, [0, 1, 4]);
        assert_eq!(table.widths.get(), [px(100.); 3]);
        assert_eq!(table.toggle(0, Some(4)), Some(4));
        assert_eq!(table.visible, [0, 4]);
        table.toggle(0, None);
        assert_eq!(table.visible, [0, 1, 4]);
        table.toggle(1, None);
        assert_eq!(table.visible, [0, 1, 2, 3, 4]);
        assert_eq!(table.widths.get(), [px(100.); 3]);
        let fresh = Table::new(&script, &AtomicBool::new(false))?;
        assert_eq!(fresh.visible, [0, 4]);
        assert_eq!(fresh.widths.get(), [px(0.); 3]);
        Ok(())
    }

    #[test]
    fn raw_record_bytes_wrap_without_truncating_or_changing_offsets() -> anyhow::Result<()> {
        let bytes: Vec<u8> = (0..=255).collect();
        let script = script(vec![arg(
            A::Data,
            0x1_0000_0010,
            Value::Bytes(bytes.clone()),
        )]);
        let mut table = Table::new(&script, &AtomicBool::new(false))?;
        table.toggle(0, None);
        assert_eq!(table.rows[1].cells[2].as_ref(), "256 bytes");
        assert_eq!(table.rows[2].cells[0].as_ref(), "100000010");
        let end = table.rows[1].end;
        let decoded = table.rows[2..end]
            .iter()
            .flat_map(|row| row.cells[2].split_whitespace())
            .map(|byte| u8::from_str_radix(byte, 16))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(decoded, bytes);
        assert_eq!(table.rows[end - 1].cells[0].as_ref(), "1000000F0");
        assert_eq!(table.toggle(1, Some(end - 1)), Some(1));
        assert_eq!(table.visible, [0, 1, end]);
        Ok(())
    }

    #[test]
    fn empty_records_and_empty_groups_remain_visible_without_disclosures() -> anyhow::Result<()> {
        let empty = Table::new(&script(Vec::new()), &AtomicBool::new(false))?;
        assert!(!empty.expandable(0));
        let mut table = Table::new(
            &script(vec![arg(A::Constants, 8, Value::Group(Vec::new()))]),
            &AtomicBool::new(false),
        )?;
        table.toggle(0, None);
        assert_eq!(table.rows[1].cells[1].as_ref(), "constants");
        assert_eq!(table.rows[1].cells[2].as_ref(), "{}");
        assert!(!table.expandable(1));
        Ok(())
    }

    #[test]
    fn pinned_headers_follow_ancestry_and_leave_when_scrolled_past_the_record() -> anyhow::Result<()>
    {
        let mut table = Table::new(
            &script(vec![
                arg(
                    A::Resources,
                    8,
                    Value::Group(vec![
                        arg(A::ValueAt(0), 8, Value::DataAddress(100)),
                        arg(A::ValueAt(1), 12, Value::DataAddress(104)),
                    ]),
                ),
                arg(
                    A::Labels,
                    16,
                    Value::Group(vec![
                        arg(A::ValueAt(0), 16, Value::CodeAddress(200)),
                        arg(A::ValueAt(1), 20, Value::CodeAddress(204)),
                    ]),
                ),
            ]),
            &AtomicBool::new(false),
        )?;
        assert!(table.sticky_rows(0).is_empty());
        assert!(table.sticky_rows(1).is_empty());
        table.toggle(0, None);
        assert_eq!(table.visible, (0..8).collect::<Vec<_>>());
        for first in 1..=4 {
            assert_eq!(table.sticky_rows(first), [0, 1], "first item {first}");
        }
        for first in 5..=7 {
            assert_eq!(table.sticky_rows(first), [0, 4], "first item {first}");
        }
        assert!(table.sticky_rows(8).is_empty());
        assert!(table.sticky_rows(9).is_empty());
        table.toggle(4, None);
        assert_eq!(table.sticky_rows(5), [0]);
        table.toggle(0, None);
        assert!(table.sticky_rows(1).is_empty());
        assert!(table.sticky_rows(2).is_empty());
        Ok(())
    }

    #[test]
    fn pinned_headers_include_each_nested_group_without_repeating_rows() -> anyhow::Result<()> {
        let mut table = Table::new(
            &script(vec![arg(
                A::Metadata,
                8,
                Value::Group(vec![arg(
                    A::Resources,
                    8,
                    Value::Group(vec![arg(A::ValueAt(0), 8, Value::Unsigned(1))]),
                )]),
            )]),
            &AtomicBool::new(false),
        )?;
        table.toggle(0, None);
        assert_eq!(table.sticky_rows(1), [0, 1, 2]);
        assert_eq!(table.sticky_rows(4), [0, 1, 2]);
        table.toggle(1, None);
        assert_eq!(table.sticky_rows(1), [0]);
        assert!(table.sticky_rows(3).is_empty());
        Ok(())
    }
}
