//! Set NVLENS_SYSTEMNNN_GAME to an owned Extravaganza Mushigurui Hen install.
//! cargo test -p nvlens-script --test systemnnn_records -- --ignored --nocapture
//! All checks read script data only; no images or GUI are opened.
use nvlens_core::{Error, Result};
use nvlens_script::ir::{ArgName as A, DataOperation, Operation, Qualifier as Q, Value};
use std::{collections::BTreeMap, path::PathBuf};
#[test]
#[ignore = "Requires NVLENS_SYSTEMNNN_GAME pointing to an owned game installation"]
fn validates_record_tables_and_string_pools() -> Result<()> {
    let root =
        PathBuf::from(std::env::var_os("NVLENS_SYSTEMNNN_GAME").ok_or(Error::InvalidFormat)?)
            .join("spt");
    nvlens_script::init();
    let mut variants = BTreeMap::new();
    let mut string_count = 0;
    let mut unresolved_header_words = 0;
    let mut unknown_auxiliary_words = 0;
    let mut opaque_bytes = 0;
    let mut choice_cases = 0;
    for path in std::fs::read_dir(root)? {
        let path = path?.path();
        if path.extension().is_none_or(|ext| ext != "spt") {
            continue;
        }
        let bytes = std::fs::read(&path)?;
        let data = nvlens_script::decode_as("spt/systemnnn", &bytes, &Default::default())?;
        let script = nvlens_script::disassemble_as("spt/systemnnn", &data, None)?
            .ok_or(Error::InvalidFormat)?;
        assert_eq!(script.sections[0].raw, data.as_ref());
        for instruction in &script.instructions {
            if instruction.opcode.code == 0x22220006 {
                let targets = instruction
                    .args
                    .iter()
                    .find(|arg| arg.name == A::Targets)
                    .ok_or(Error::InvalidFormat)?;
                let Value::Group(cases) = &targets.value else {
                    return Err(Error::InvalidFormat);
                };
                choice_cases += cases.len();
                continue;
            }
            if instruction.opcode.operation != Operation::Data(DataOperation::Record) {
                continue;
            }
            let variant = instruction.opcode.variant.ok_or(Error::InvalidFormat)?;
            *variants.entry(variant.name()).or_insert(0usize) += 1;
            let mut pending: Vec<_> = instruction.args.iter().collect();
            while let Some(arg) = pending.pop() {
                assert!(arg.span.offset + arg.span.size <= data.len() as u64);
                match &arg.value {
                    Value::Group(fields) => pending.extend(fields),
                    Value::Bytes(bytes) if arg.name == A::Data => opaque_bytes += bytes.len(),
                    Value::Unsigned(_)
                        if matches!(arg.name, A::Unknown(_)) && variant == Q::ScriptMetadata =>
                    {
                        unresolved_header_words += 1
                    }
                    Value::Unsigned(_)
                        if matches!(arg.name, A::Unknown(_)) && variant == Q::WordTable =>
                    {
                        unknown_auxiliary_words += 1
                    }
                    _ => {}
                }
                if matches!(arg.name, A::StringAt(_)) {
                    string_count += 1;
                }
            }
        }
    }
    for variant in [
        Q::ScriptMetadata,
        Q::LabelTable,
        Q::WordTable,
        Q::AddressTable,
        Q::MessageTable,
        Q::ResourceTable,
        Q::ConstantTable,
        Q::ReturnTable,
        Q::ChoiceTable,
        Q::CommandTable,
        Q::ScriptTable,
    ] {
        assert_eq!(variants.get(variant.name()), Some(&7), "{variant:?}");
    }
    assert_eq!(variants.get(Q::BlockBegin.name()), Some(&78));
    assert_eq!(variants.get(Q::BlockEnd.name()), Some(&78));
    assert_eq!(unresolved_header_words, 77);
    assert_eq!(unknown_auxiliary_words, 140);
    assert_eq!(string_count, 33_609);
    assert_eq!(choice_cases, 13);
    assert_eq!(
        opaque_bytes, 0,
        "Unparsed payload bytes remain in sample data records"
    );
    println!(
        "Variants {variants:?}; strings {string_count}; unknown header words {unresolved_header_words}; unknown auxiliary words {unknown_auxiliary_words}; opaque bytes {opaque_bytes}; choice cases {choice_cases}"
    );
    Ok(())
}
