use super::*;
use nvlens_io::BinaryWriter;
fn words(values: &[u32]) -> Vec<u8> {
    let mut bytes = vec![0; values.len() * 4];
    for (&v, b) in values.iter().zip(bytes.as_chunks_mut::<4>().0) {
        BinaryWriter::u32_le(v, b);
    }
    bytes
}
#[test]
fn sv20_operands_and_missing_companions() -> Result<()> {
    let bytes = words(&[
        0x30327653, 0, 12, 0x10001, 0x40000000, 7, 0x1001f, 8, 0x1000b, 0, 0x10018,
    ]);
    let script = Softpal
        .disassemble(&bytes, None)?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(script.instructions.len(), 4);
    assert_eq!(script.sections[0].raw, bytes);
    assert_eq!(script.instructions[0].args[0].attributes[0].value, 4);
    assert!(matches!(
        script.instructions[2].args[0].value,
        Value::CodeAddress(12)
    ));
    assert!(Softpal.disassemble(&bytes[..15], None).is_err());
    Ok(())
}
#[test]
fn lists_decrypt_once_and_decode_cp932() -> Result<()> {
    let mut logical = b"$TEXT_LIST__".to_vec();
    logical.extend(words(&[1, 17]));
    logical.extend(b"hello\0");
    let mut encrypted = logical.clone();
    for (index, part) in encrypted[16..]
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .enumerate()
    {
        BinaryWriter::u32_le(BinaryReader::u32_le(part) ^ 0xf7d5859d, part);
        part[0] = part[0].rotate_right(index as u32 + 4);
    }
    assert_eq!(&*decode_envelope(&encrypted)?, &logical);
    assert_eq!(Softpal.decode_text(&logical)?, Some("17\thello".into()));
    assert!(decode_envelope(b"$TEXT_LIST__").is_err());
    Ok(())
}
