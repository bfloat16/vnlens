use super::*;
use nvlens_io::BinaryWriter;
fn word(b: &mut Vec<u8>, v: u32) {
    let p = b.len();
    b.resize(p + 4, 0);
    BinaryWriter::u32_le(v, &mut b[p..]);
}
fn short(b: &mut Vec<u8>, v: i16) {
    let p = b.len();
    b.resize(p + 2, 0);
    BinaryWriter::u16_le(v as u16, &mut b[p..]);
}
fn fixture(code: &[i16]) -> Vec<u8> {
    let mut data = vec![0; 20];
    word(&mut data, 1);
    let text = "日本😀";
    word(&mut data, text.encode_utf16().count() as u32);
    for w in text.encode_utf16() {
        short(&mut data, w as i16);
    }
    while !data.len().is_multiple_of(4) {
        data.push(0);
    }
    word(&mut data, 0);
    let mut object = vec![0; 48];
    word(&mut object, 1);
    word(&mut object, 0);
    word(&mut object, 42);
    word(&mut object, code.len() as u32);
    for &w in code {
        short(&mut object, w);
    }
    while !object.len().is_multiple_of(4) {
        object.push(0);
    }
    word(&mut object, 1);
    short(&mut object, 3);
    short(&mut object, 0);
    word(&mut object, 0);
    word(&mut object, 0);
    let mut objects = Vec::new();
    word(&mut objects, 0);
    word(&mut objects, 1);
    objects.extend(b"TJS2");
    word(&mut objects, object.len() as u32);
    objects.extend(object);
    let mut bytes = b"TJS2100\0".to_vec();
    word(&mut bytes, 0);
    for (tag, payload) in [(b"DATA", data), (b"OBJS", objects)] {
        bytes.extend(tag);
        word(&mut bytes, (payload.len() + 8) as u32);
        bytes.extend(payload);
    }
    let len = bytes.len() as u32;
    BinaryWriter::u32_le(len, &mut bytes[8..]);
    bytes
}
#[test]
fn constants_expanded_calls_source_spans_and_unknown_tail() -> Result<()> {
    let bytes = fixture(&[1, 1, 0, 100, 2, -2, 0, -2, 1, 0, 1, 119, 200, 7, 8]);
    let script = parse(&bytes)?;
    assert_eq!(script.instructions.len(), 4);
    assert!(matches!(&script.instructions[0].args[1].value,Value::Text(s) if s=="日本😀"));
    assert!(matches!(
        script.instructions[1].opcode.operation,
        Operation::ControlFlow(ControlFlowOperation::Call)
    ));
    assert!(matches!(
        script.instructions[3].opcode.operation,
        Operation::Unknown
    ));
    assert_eq!(script.sections[0].raw, bytes);
    assert!(
        script.instructions[0]
            .attributes
            .iter()
            .any(|a| a.name == "source_offset" && a.value == 42)
    );
    assert!(parse(&fixture(&[1, 1])).is_err());
    assert!(parse(&fixture(&[17, i16::MAX])).is_err());
    for len in 0..bytes.len() {
        assert!(parse(&bytes[..len]).is_err());
    }
    Ok(())
}
#[test]
fn name_hints_fold_known_register_strings_without_crossing_branches() -> Result<()> {
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let direct = fixture(&[1, 1, 0, 2, 2, 1, 58, 1, 2, 119]);
    let names = crate::krkr::name_candidates(&direct, "test.tjs", &cancel)?;
    assert!(names.contains(&"日本😀日本😀".into()));
    let branched = fixture(&[1, 1, 0, 2, 2, 1, 17, 2, 58, 1, 2, 119]);
    assert!(
        !crate::krkr::name_candidates(&branched, "test.tjs", &cancel)?
            .contains(&"日本😀日本😀".into())
    );
    Ok(())
}
