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
