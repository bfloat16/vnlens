//! Adapts parsed PSB values to the shared expandable preview table. Parsing and
//! JSON serialization remain in the script crate; resource bodies stay unread.
use super::*;
use nvlens_script::psb::{Psb, PsbNumber, PsbValue};

impl Table {
    pub(crate) fn from_psb(psb: &Psb, cancelled: &AtomicBool) -> nvlens_core::Result<Self> {
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
                return Err(nvlens_core::Error::Cancelled);
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
                            return Err(nvlens_core::Error::Cancelled);
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
    pub(crate) fn psb_json(&self, row: usize, psb: &Psb) -> Option<nvlens_core::Result<String>> {
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
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::prelude::rust_2024::test;

    fn psb(root: PsbValue) -> Psb {
        Psb {
            data_len: 0,
            names: Vec::new(),
            strings: Vec::new(),
            resources: Vec::new(),
            extra_resources: Vec::new(),
            root,
        }
    }

    #[test]
    fn nested_psb_rows_share_collapse_pinning_selection_and_width_state() -> anyhow::Result<()> {
        let psb = psb(PsbValue::Object(BTreeMap::from([
            ("empty".into(), PsbValue::Object(BTreeMap::new())),
            (
                "scenes".into(),
                PsbValue::List(vec![PsbValue::Object(BTreeMap::from([(
                    "text".into(),
                    PsbValue::String {
                        index: 9,
                        value: "日本語\n\t".repeat(1000),
                    },
                )]))]),
            ),
        ])));
        let exported = psb.to_json()?;
        let mut table = Table::from_psb(&psb, &AtomicBool::new(false))?;
        assert_eq!(table.visible, [0, 1, 2]);
        assert_eq!(table.rows[0].cells[2].as_ref(), "2 fields");
        assert_eq!(table.rows[1].cells[2].as_ref(), "0 fields");
        assert!(!table.expandable(1));
        assert_eq!(table.rows[2].cells[2].as_ref(), "1 items");
        table.toggle(2, None);
        assert_eq!(table.visible, [0, 1, 2, 3]);
        assert_eq!(table.rows[3].cells[1].as_ref(), "[0]");
        table.toggle(3, None);
        assert_eq!(table.visible, [0, 1, 2, 3, 4]);
        assert_eq!(table.sticky_rows(5), [0, 2, 3]);
        assert_eq!(
            table.rows[4].cells[2].as_ref(),
            format!("{:?}", "日本語\n\t".repeat(1000))
        );
        table.widths.set([px(100.); 3]);
        assert_eq!(table.toggle(2, Some(4)), Some(2));
        assert_eq!(table.visible, [0, 1, 2]);
        assert_eq!(table.widths.get(), [px(100.); 3]);
        table.toggle(2, None);
        assert_eq!(table.visible, [0, 1, 2, 3, 4]);
        assert_eq!(psb.to_json()?, exported);
        Ok(())
    }

    #[test]
    fn psb_scalars_and_arrays_preserve_values_and_original_keys_when_copied() -> anyhow::Result<()>
    {
        let psb = psb(PsbValue::Object(BTreeMap::from([
            ("".into(), PsbValue::Null),
            ("array".into(), PsbValue::Array(vec![0, u32::MAX])),
            ("false".into(), PsbValue::Bool(false)),
            (
                "float".into(),
                PsbValue::Number(PsbNumber::Float(f32::from_bits(0x7fc01234))),
            ),
            (
                "integer".into(),
                PsbValue::Number(PsbNumber::Integer(i64::MIN)),
            ),
            ("list".into(), PsbValue::List(Vec::new())),
            (
                "negative_zero".into(),
                PsbValue::Number(PsbNumber::Double(-0.0)),
            ),
            (
                "resource".into(),
                PsbValue::Resource {
                    index: 17,
                    is_extra: true,
                },
            ),
            (
                "text\n\t".into(),
                PsbValue::String {
                    index: 0,
                    value: String::new(),
                },
            ),
            ("text\\n\\t".into(), PsbValue::Bool(true)),
        ])));
        let table = Table::from_psb(&psb, &AtomicBool::new(false))?;
        let fields = psb
            .root
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("Missing fields"))?;
        for row in 0..table.rows.len() {
            let expected = match &table.rows[row].source {
                Source::Root => psb.to_json()?,
                Source::Property(key) => fields[key].to_json()?,
                Source::Index(index) => format!("{}\n", [0, u32::MAX][*index]),
                _ => return Err(anyhow::anyhow!("Unexpected instruction")),
            };
            assert_eq!(table.psb_json(row, &psb).transpose()?, Some(expected));
            assert!(table.instruction_index(row).is_none());
        }
        assert!(
            table
                .rows
                .iter()
                .any(|row| row.cells[2].contains("$float_bits"))
        );
        assert!(table.rows.iter().any(|row| row.cells[2].as_ref() == "-0.0"));
        assert!(
            table
                .rows
                .iter()
                .any(|row| row.cells[2].contains("$resource"))
        );
        Ok(())
    }

    #[test]
    fn psb_traversal_is_iterative_and_cancellable() -> anyhow::Result<()> {
        let mut root = PsbValue::Null;
        for _ in 0..2048 {
            root = PsbValue::List(vec![root]);
        }
        let psb = psb(root);
        let table = Table::from_psb(&psb, &AtomicBool::new(false))?;
        assert_eq!(table.rows.len(), 2049);
        assert_eq!(table.visible, [0, 1]);
        assert_eq!(
            table.psb_json(2048, &psb).transpose()?,
            Some("null\n".into())
        );
        assert!(matches!(
            Table::from_psb(&psb, &AtomicBool::new(true)),
            Err(nvlens_core::Error::Cancelled)
        ));
        Ok(())
    }
}
