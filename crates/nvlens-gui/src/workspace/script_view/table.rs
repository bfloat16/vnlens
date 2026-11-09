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
#[path = "../../../tests/workspace/script_view/table.rs"]
mod tests;
