use super::*;
use vnlens_io::BinaryWriter;

fn action(call: u32, opcode: u32, triples: &[[u32; 3]], payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0; 16 + triples.len() * 12 + payload.len()];
    let size = data.len() as u32;
    for (i, value) in [call, opcode, triples.len() as u32, size]
        .into_iter()
        .enumerate()
    {
        BinaryWriter::u32_le(value, &mut data[i * 4..]);
    }
    for (i, triple) in triples.iter().enumerate() {
        for (j, value) in triple.iter().enumerate() {
            BinaryWriter::u32_le(*value, &mut data[16 + i * 12 + j * 4..]);
        }
    }
    data[size as usize - payload.len()..].copy_from_slice(payload);
    data
}
fn fixture(actions: &[Vec<u8>]) -> Vec<u8> {
    let mut data = vec![0; 0x50];
    data[..6].copy_from_slice(b"STCM2L");
    BinaryWriter::u32_le(2, &mut data[0x28..]);
    data.extend_from_slice(b"GLOBAL_DATA\0CODE_START_\0");
    for action in actions {
        data.extend_from_slice(action);
    }
    data.extend_from_slice(b"EXPORT_DATA\0");
    let exports = data.len() as u32;
    BinaryWriter::u32_le(exports, &mut data[0x20..]);
    BinaryWriter::u32_le(2, &mut data[0x24..]);
    for name in [b"start", b"alias"] {
        let mut row = [0; 40];
        row[4..9].copy_from_slice(name);
        BinaryWriter::u32_le(0x68, &mut row[36..]);
        data.extend_from_slice(&row);
    }
    data.extend_from_slice(b"COLLECTION_LINK\0");
    let link = data.len() as u32;
    BinaryWriter::u32_le(link, &mut data[0x2c..]);
    data
}

#[test]
fn lossless_unknown_parameters_objects_and_export_aliases() -> Result<()> {
    let mut object = vec![0; 20];
    for (at, value) in [(4, 1), (8, 1), (12, 4), (16, 0x006f_7000)] {
        BinaryWriter::u32_le(value, &mut object[at..]);
    }
    let data = fixture(&[action(
        0,
        0xa75,
        &[
            [0x90, 0x4000_0000, 0x4000_0000],
            [0xdead_beef, 0x1234_5678, 0x8765_4321],
        ],
        &object,
    )]);
    let script = parse(&data, &AtomicBool::new(false))?;
    assert_eq!(script.sections[0].raw, data);
    assert_eq!(script.instructions[1].opcode.operation, Operation::Unknown);
    let Value::Group(unknown) = &script.instructions[1].args[1].value else {
        return Err(Error::InvalidFormat);
    };
    assert!(matches!(&unknown[0].value, Value::Bytes(raw) if raw == &data[0x84..0x90]));
    let Value::Group(fields) = &script.instructions[1].args[0].value else {
        return Err(Error::InvalidFormat);
    };
    assert!(!fields.iter().any(|arg| matches!(arg.value, Value::Text(_))));
    assert_eq!(script.instructions.len(), 4);
    Ok(())
}

#[test]
fn explicit_strings_and_immediates_preserve_raw_triples() -> Result<()> {
    let mut object = vec![0; 20];
    BinaryWriter::u32_le(1, &mut object[4..]);
    BinaryWriter::u32_le(1, &mut object[8..]);
    BinaryWriter::u32_le(4, &mut object[12..]);
    object[16..].copy_from_slice(b"op\0\0");
    let data = fixture(&[action(
        0,
        0x50,
        &[[0x90, 0x4000_0000, 0x4000_0000], [0x4000_002a, 5, 6]],
        &object,
    )]);
    let script =
        crate::disassemble_as("stcm2/otomate", &data, None)?.ok_or(Error::InvalidFormat)?;
    assert_eq!(
        script.instructions[1].opcode.native_mnemonic.as_deref(),
        Some("strcpy")
    );
    assert!(script.instructions[1].args_disassembly().contains("\"op\""));
    let Value::Group(fields) = &script.instructions[1].args[1].value else {
        return Err(Error::InvalidFormat);
    };
    assert!(
        fields
            .iter()
            .any(|arg| matches!(arg.value, Value::Unsigned(42)))
    );
    assert!(matches!(&fields[0].value, Value::Bytes(raw) if raw.len() == 12));
    Ok(())
}

#[test]
fn validates_action_and_reference_boundaries_and_preserves_cancellation() -> Result<()> {
    let valid = fixture(&[action(1, 0x68, &[[0xffff_ff41, 0x68, 0x4000_0000]], &[])]);
    let script = parse(&valid, &AtomicBool::new(false))?;
    assert_eq!(
        script.instructions[1].opcode.operation,
        Operation::ControlFlow(ControlFlowOperation::Call)
    );
    let mut invalid = valid.clone();
    BinaryWriter::u32_le(0x69, &mut invalid[0x6c..]);
    assert!(matches!(
        parse(&invalid, &AtomicBool::new(false)),
        Err(Error::Corrupt { .. })
    ));
    let mut invalid = valid.clone();
    BinaryWriter::u32_le(15, &mut invalid[0x74..]);
    assert!(matches!(
        parse(&invalid, &AtomicBool::new(false)),
        Err(Error::Corrupt { .. })
    ));
    for end in 0..valid.len() - 16 {
        assert!(parse(&valid[..end], &AtomicBool::new(false)).is_err());
    }
    assert!(matches!(
        parse(&valid, &AtomicBool::new(true)),
        Err(Error::Cancelled)
    ));
    Ok(())
}

#[test]
fn action_count_follows_storage_without_an_artificial_threshold() -> Result<()> {
    let data = fixture(&vec![action(0, 0, &[], &[]); 0x1001]);
    let script = parse(&data, &AtomicBool::new(false))?;
    assert_eq!(script.instructions.len(), 0x1004);
    Ok(())
}
