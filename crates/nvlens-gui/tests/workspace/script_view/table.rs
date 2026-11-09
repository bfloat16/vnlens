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
fn pinned_headers_follow_ancestry_and_leave_when_scrolled_past_the_record() -> anyhow::Result<()> {
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
