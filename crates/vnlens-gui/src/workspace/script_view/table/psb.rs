//! Adapts parsed PSB values to the shared expandable preview table. Parsing and
//! JSON serialization remain in the script crate; resource bodies stay unread.
use super::*;
use vnlens_script::psb::{Psb, PsbNumber, PsbValue};

impl Table {
    pub(crate) fn from_psb(psb: &Psb, cancelled: &AtomicBool) -> vnlens_core::Result<Self> {
        enum Pending<'a> {
            Value(&'a PsbValue, Source, Option<usize>),
            End(usize),
        }
        let mut table = Self {
            headers: &["Type", "Field / Index", "Value"],
            rows: Vec::new(),
            visible: vec![0],
            widths: Cell::new([px(0.); 3]),
        };
        let mut pending = vec![Pending::Value(&psb.root, Source::Root, None)];
        while let Some(item) = pending.pop() {
            if cancelled.load(Ordering::Relaxed) {
                return Err(vnlens_core::Error::Cancelled);
            }
            let (value, source, parent) = match item {
                Pending::Value(value, source, parent) => (value, source, parent),
                Pending::End(row) => {
                    table.rows[row].end = table.rows.len();
                    continue;
                }
            };
            let name = match &source {
                Source::Property(key) => key.clone(),
                Source::Index(index) => format!("[{index}]"),
                _ => "PSB".into(),
            };
            let kind = match value {
                PsbValue::Null => "null",
                PsbValue::Bool(_) => "boolean",
                PsbValue::Number(PsbNumber::Integer(_)) => "integer",
                PsbValue::Number(PsbNumber::Float(_)) => "float32",
                PsbValue::Number(PsbNumber::Double(_)) => "float64",
                PsbValue::String { .. } => "string",
                PsbValue::Resource { .. } => "resource",
                PsbValue::Array(_) => "array",
                PsbValue::List(_) => "list",
                PsbValue::Object(_) => "object",
            };
            let text = match value {
                PsbValue::Object(fields) => format!("{} fields", fields.len()),
                PsbValue::List(values) => format!("{} items", values.len()),
                PsbValue::Array(values) => format!("{} items", values.len()),
                _ => value.to_json()?.trim_end_matches('\n').to_owned(),
            };
            let row = table.push(source, parent, [kind.into(), name, text]);
            table.rows[row].expanded = false;
            pending.push(Pending::End(row));
            match value {
                PsbValue::Object(fields) => {
                    pending.extend(fields.iter().rev().map(|(key, value)| {
                        Pending::Value(value, Source::Property(key.clone()), Some(row))
                    }))
                }
                PsbValue::List(values) => {
                    pending.extend(values.iter().enumerate().rev().map(|(index, value)| {
                        Pending::Value(value, Source::Index(index), Some(row))
                    }))
                }
                PsbValue::Array(values) => {
                    for (index, value) in values.iter().enumerate() {
                        if cancelled.load(Ordering::Relaxed) {
                            return Err(vnlens_core::Error::Cancelled);
                        }
                        table.push(
                            Source::Index(index),
                            Some(row),
                            ["unsigned".into(), format!("[{index}]"), value.to_string()],
                        );
                    }
                }
                _ => {}
            }
        }
        // Show the root's immediate fields; nested containers open on demand.
        table.toggle(0, None);
        Ok(table)
    }

    /// Resolves the stable row through its original keys/indices. Display text
    /// may escape control characters, so it must not be used as a lookup key.
    pub(crate) fn psb_json(&self, row: usize, psb: &Psb) -> Option<vnlens_core::Result<String>> {
        let mut path = Vec::new();
        let mut ancestor = Some(row);
        while let Some(row) = ancestor {
            let row = self.rows.get(row)?;
            path.push(&row.source);
            ancestor = row.parent;
        }
        let mut value = &psb.root;
        for source in path.into_iter().rev() {
            value = match (source, value) {
                (Source::Root, _) => value,
                (Source::Property(key), PsbValue::Object(fields)) => fields.get(key)?,
                (Source::Index(index), PsbValue::List(values)) => values.get(*index)?,
                (Source::Index(index), PsbValue::Array(values)) => {
                    return Some(Ok(format!("{}\n", values.get(*index)?)));
                }
                _ => return None,
            };
        }
        Some(value.to_json())
    }
}

#[cfg(test)]
#[path = "../../../../tests/workspace/script_view/table/psb.rs"]
mod tests;
