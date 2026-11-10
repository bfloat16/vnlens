use super::*;
#[test]
fn reference_ancestors_locate_the_target_without_becoming_siblings() -> Result<()> {
    let mut data = vec![0; 27];
    for (start, tag, offset) in [(1, 0x8003, 512u32), (13, 0x8002, 256)] {
        BinaryWriter::u16_le(tag, &mut data[start..]);
        BinaryWriter::u16_le(0x8008, &mut data[start + 2..]);
        BinaryWriter::u32_le(OFFSET_BIAS.wrapping_add(offset), &mut data[start + 4..]);
        BinaryWriter::u32_le(
            SIZE_BIAS.wrapping_add((3 << 13) | 3),
            &mut data[start + 8..],
        );
    }
    data.extend([0, 0]);
    let mut reader = Reader::new(&data, true);
    for name in ["CObjectOcean", "CRsa"] {
        reader.map_class(Class {
            name: name.into(),
            schema: 1,
            encoded: None,
        });
    }
    assert!(matches!(reader.reference()?, Reference::External(object) if object.offset == 512));
    assert_eq!(reader.objects.len(), 1);
    assert_eq!(reader.objects[0].class.name, "CRsa");
    assert_eq!(reader.bytes.remaining(), 0);
    let mut cached = [0; 2];
    BinaryWriter::u16_le(5, &mut cached);
    let mut reader = reader.with_data(&cached);
    assert!(matches!(reader.reference()?, Reference::External(object) if object.offset == 512));
    assert_eq!(reader.objects.len(), 2);
    Ok(())
}
#[test]
fn class_names_and_mfc_unicode_have_format_bounds() -> Result<()> {
    assert_eq!(
        class_name(&[0x3a, 0xa6, 0x31, 0xe0, 0x99, 0x0a, 0xff], 0)?,
        "CMsgSelBox"
    );
    assert_eq!(
        string(&mut BinaryReader::new(&[255, 254, 255, 1, 0x42, 0x30]))?,
        "あ"
    );
    assert!(string(&mut BinaryReader::new(&[255, 254, 255, 1, 0x42])).is_err());
    assert!(count(&mut BinaryReader::new(&[255, 255, 1])).is_err());
    Ok(())
}
