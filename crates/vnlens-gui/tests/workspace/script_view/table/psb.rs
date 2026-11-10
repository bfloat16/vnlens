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
fn psb_scalars_and_arrays_preserve_values_and_original_keys_when_copied() -> anyhow::Result<()> {
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
        Err(vnlens_core::Error::Cancelled)
    ));
    Ok(())
}
