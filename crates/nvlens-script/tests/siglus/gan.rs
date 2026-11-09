use super::*;
use nvlens_io::BinaryWriter;
#[test]
fn animation_records_preserve_signed_offsets_and_reject_unknown_layout() -> Result<()> {
    let words = [
        10000,
        10000,
        20000,
        1,
        30000,
        1,
        30100,
        2,
        30101,
        u32::MAX,
        30103,
        60,
        30104,
        128,
        999999,
    ];
    let mut bytes = vec![0; words.len() * 4];
    for (i, word) in words.into_iter().enumerate() {
        BinaryWriter::u32_le(word, &mut bytes[i * 4..]);
    }
    let script = parse(&bytes)?;
    assert_eq!(script.instructions.len(), 2);
    assert!(
        script.instructions[1]
            .args
            .iter()
            .any(|o| o.name == ArgName::OffsetX && matches!(o.value, Value::Integer(-1)))
    );
    assert_eq!(script.sections[0].raw, bytes);
    assert!(parse(&bytes[..bytes.len() - 1]).is_err());
    BinaryWriter::u32_le(30199, &mut bytes[24..]);
    assert!(parse(&bytes).is_err());
    Ok(())
}
