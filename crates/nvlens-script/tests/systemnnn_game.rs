//! Set NVLENS_SYSTEMNNN_GAME to an owned Extravaganza Mushigurui Hen install.
//! Run with cargo test -p nvlens-script --test systemnnn_game -- --ignored --nocapture.
//! Only script bytes are read; no game or GUI is launched.
use nvlens_core::{Error, ResourceResolver, Result};
use nvlens_script::ir::{Arg, ArgName, Operation, Qualifier, Value};
use std::{collections::BTreeMap, path::PathBuf};

struct Resources(PathBuf);
impl ResourceResolver for Resources {
    fn read_resource(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.0.join(name)) {
            Ok(data) => Ok(Some(data)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

fn check_args(args: &[Arg], data: &[u8], counts: &mut BTreeMap<&'static str, usize>) {
    let mut pending: Vec<_> = args.iter().collect();
    while let Some(arg) = pending.pop() {
        assert!(arg.span.offset + arg.span.size <= data.len() as u64);
        match &arg.value {
            Value::Expression(items) => {
                for item in items {
                    assert_ne!(item.opcode.operation, Operation::Unknown);
                    let start = item.span.offset as usize;
                    let end = start + item.span.size as usize;
                    assert_eq!(item.raw, data[start..end]);
                    *counts.entry(item.opcode.operation.name()).or_default() += 1;
                    if item.opcode.code == 0xa200002b {
                        assert_eq!(item.opcode.operation.name(), "store");
                        assert_eq!(item.opcode.variant, Some(Qualifier::AddAssign));
                    }
                    pending.extend(&item.args);
                }
            }
            Value::Group(items) => pending.extend(items),
            _ => {}
        }
    }
}

#[test]
#[ignore = "Requires NVLENS_SYSTEMNNN_GAME pointing to an owned game installation"]
fn validates_spt_semantics() -> Result<()> {
    let root =
        PathBuf::from(std::env::var_os("NVLENS_SYSTEMNNN_GAME").ok_or(Error::InvalidFormat)?)
            .join("spt");
    let resolver = Resources(root.clone());
    nvlens_script::init();
    let mut operations = BTreeMap::new();
    let mut token_operations = BTreeMap::new();
    let mut unknown = BTreeMap::new();
    let mut total = 0;
    for (name, count) in [
        ("BCmkri_backscript.spt", 1745),
        ("etc.spt", 343),
        ("s100.spt", 24067),
        ("s200.spt", 7762),
        ("s300.spt", 53279),
        ("s400.spt", 14274),
        ("sys.spt", 41),
    ] {
        let raw = std::fs::read(root.join(name))?;
        let decoded = nvlens_script::decode_as("spt/systemnnn", &raw, &Default::default())?;
        let script = nvlens_script::disassemble_as("spt/systemnnn", &decoded, Some(&resolver))?
            .ok_or(Error::InvalidFormat)?;
        assert_eq!(script.instructions.len(), count, "{name}");
        assert_eq!(script.sections[0].raw, decoded.as_ref());
        total += count;
        let mut next = 0;
        for instruction in &script.instructions {
            assert_eq!(instruction.span.offset, next);
            next += instruction.span.size;
            *operations
                .entry(instruction.opcode.operation.name())
                .or_insert(0usize) += 1;
            if instruction.opcode.operation == Operation::Unknown {
                *unknown
                    .entry((
                        instruction.opcode.namespace.clone(),
                        instruction.opcode.code,
                    ))
                    .or_insert(0usize) += 1;
            }
            check_args(&instruction.args, &decoded, &mut token_operations);
            if instruction.opcode.code == 0x55560009 {
                assert_eq!(instruction.args[0].name, ArgName::LabelId);
                assert_eq!(instruction.args[1].name, ArgName::ResolvedTarget);
                assert_eq!(instruction.args[1].span.size, 0);
            }
        }
        assert_eq!(next, decoded.len() as u64);
    }
    assert!(unknown.is_empty(), "Unmapped native opcodes: {unknown:?}");
    assert_eq!(total, 101_511);
    assert_eq!(operations.get("store"), Some(&44));
    assert_eq!(operations.get("set_image_visibility"), Some(&16));
    assert_eq!(operations.get("capture_image"), Some(&2798));
    assert_eq!(operations.get("mark_seen"), Some(&503));
    assert_eq!(operations.get("stop_skip"), Some(&19));
    assert!(!operations.contains_key("engine_call"));
    println!(
        "{total} records; operations {operations:?}; expression operations {token_operations:?}"
    );
    Ok(())
}
