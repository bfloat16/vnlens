use super::*;
use nvlens_io::BinaryWriter;

fn put(bytes: &mut [u8], index: usize, value: u32) {
    BinaryWriter::u32_le(value, &mut bytes[index * 4..]);
}
fn header_bytes() -> Vec<u8> {
    let mut data = vec![0; 128];
    for (index, value) in [(0, 32), (1, 0x66660001), (2, 0x55550001)] {
        put(&mut data, index, value);
    }
    data[48..58].copy_from_slice(b"SPTHEADER0");
    data[58..63].fill(b' ');
    data
}
fn record(data: &mut Vec<u8>, subtype: u32, payload: &[u8]) -> usize {
    let start = data.len();
    data.resize(start + 16, 0);
    for (index, value) in [
        (0, 4 + payload.len() as u32 / 4),
        (1, 0x66660001),
        (2, 0x55550002),
        (3, subtype),
    ] {
        put(&mut data[start..], index, value);
    }
    data.extend_from_slice(payload);
    start
}
#[test]
fn string_pools_preserve_aliases_suffixes_non_text_bytes_and_alignment() -> Result<()> {
    let mut data = header_bytes();
    let pool = 128 + 16 + 20;
    let mut payload = vec![0; 20];
    for (index, offset) in [0, 4, 0, 8, 12].into_iter().enumerate() {
        put(&mut payload, index, ((pool + offset) / 4) as u32);
    }
    payload.extend_from_slice(b"abcdefgh\0\xaa\xbb\xcc\x81\0\xdd\xee");
    let start = record(&mut data, 0x44440001, &payload);
    put(&mut data, 6, 5);
    put(&mut data, 7, (start as u32 + 16) / 4);
    let (variant, args) = parse(&data, &data[start + 12..], start, 0x55550002)?;
    assert_eq!(variant, Some(Q::ResourceTable));
    let Value::Group(pointers) = &args[1].value else {
        return Err(nvlens_core::Error::InvalidFormat);
    };
    assert_eq!(pointers.len(), 5);
    assert!(matches!(pointers[0].value,Value::DataAddress(value) if value==pool as u64));
    assert!(matches!(pointers[2].value,Value::DataAddress(value) if value==pool as u64));
    let Value::Group(strings) = &args[2].value else {
        return Err(nvlens_core::Error::InvalidFormat);
    };
    let text: Vec<_> = strings
        .iter()
        .filter_map(|item| match &item.value {
            Value::Group(fields) => Some(&fields[0].value),
            _ => None,
        })
        .collect();
    assert_eq!(text.len(), 4);
    assert!(matches!(text[0],Value::Text(value) if value=="abcdefgh"));
    assert!(matches!(text[1],Value::Text(value) if value=="efgh"));
    assert!(matches!(text[2],Value::Text(value) if value.is_empty()));
    assert!(matches!(text[3],Value::Bytes(value) if value==&[0x81]));
    assert!(strings.iter().any(|arg| arg.name == A::Padding
        && matches!(&arg.value,Value::Bytes(bytes) if bytes==&[0xaa,0xbb,0xcc])));
    let at = pool + 13;
    data[at] = 0xff;
    assert!(
        matches!(parse(&data,&data[start+12..],start,0x55550002),Err(nvlens_core::Error::Io(error)) if error.kind()==std::io::ErrorKind::UnexpectedEof)
    );
    Ok(())
}
#[test]
fn signed_constants_and_empty_tables_use_structural_variants() -> Result<()> {
    let mut data = header_bytes();
    let mut payload = vec![0; 8];
    put(&mut payload, 0, u32::MAX);
    put(&mut payload, 1, 0x80000000);
    let start = record(&mut data, 0x44440004, &payload);
    put(&mut data, 18, (start as u32 + 16) / 4);
    let (variant, args) = parse(&data, &data[start + 12..], start, 0x55550002)?;
    assert_eq!(variant, Some(Q::ConstantTable));
    let Value::Group(constants) = &args[1].value else {
        return Err(nvlens_core::Error::InvalidFormat);
    };
    assert!(matches!(constants[0].value, Value::Integer(-1)));
    assert!(matches!(constants[1].value, Value::Integer(-2147483648)));
    let start = record(&mut data, 0x44440008, &[]);
    put(&mut data, 23, (start as u32 + 16) / 4);
    let (variant, args) = parse(&data, &data[start + 12..], start, 0x55550002)?;
    assert_eq!(variant, Some(Q::ScriptTable));
    assert!(matches!(&args[1].value,Value::Group(values) if values.is_empty()));
    Ok(())
}
#[test]
fn header_signature_table_roles_and_unverified_words_keep_source_positions() -> Result<()> {
    let mut data = header_bytes();
    put(&mut data, 10, 7);
    put(&mut data, 19, 123);
    put(&mut data, 20, 36);
    let (variant, args) = parse(&data, &data[12..], 0, 0x55550001)?;
    assert_eq!(variant, Some(Q::ScriptMetadata));
    assert!(
        args.iter()
            .any(|arg| arg.name == A::LabelBase && matches!(arg.value, Value::Unsigned(7)))
    );
    assert!(args.iter().any(|arg| arg.name == A::Unknown(16)
        && arg.span.offset == 76
        && matches!(arg.value, Value::Unsigned(123))));
    let signature = args
        .iter()
        .find(|arg| arg.name == A::Signature)
        .ok_or(nvlens_core::Error::InvalidFormat)?;
    assert_eq!(signature.span.size, 16);
    assert!(matches!(&signature.value,Value::Bytes(bytes) if bytes==&data[48..64]));
    Ok(())
}
