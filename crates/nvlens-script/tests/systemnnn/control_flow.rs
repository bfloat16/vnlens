use super::*;
use nvlens_io::BinaryWriter;

#[test]
fn choices_resolve_only_case_headers_and_preserve_values_and_encoded_spans() -> Result<()> {
    let mut words = vec![0; 32];
    words[..3].copy_from_slice(&[32, 0x66660001, 0x55550001]);
    words.extend([7, 0x66660006, 0x22220006, 2, 0, 1, 7]);
    words.extend([4, 0x66660002, 0xa000007b, 28]);
    words.extend([4, 0x66660002, 0x55560008, 1]);
    words.extend([3, 0x66660002, 0x55560001]);
    words.extend([4, 0x66660002, 0x55560008, 2]);
    words.extend([4, 0x66660002, 0xa000007b, 10]);
    words.extend([3, 0x66660002, 0x55560001]);
    words.extend([3, 0x66660002, 0xa000007d]);
    words.extend([3, 0x66660002, 0xa000007d]);
    words.extend([3, 0x66660002, 0x55560006]);
    let table = words.len();
    words[6] = 2;
    words[7] = table as u32 + 4;
    words.extend([
        8,
        0x66660001,
        0x55550002,
        0x44440001,
        table as u32 + 6,
        table as u32 + 7,
        0,
        0,
    ]);
    let mut data = vec![0; words.len() * 4];
    for (&value, target) in words.iter().zip(data.as_chunks_mut::<4>().0) {
        BinaryWriter::u32_le(value, target);
    }
    data[48..58].copy_from_slice(b"SPTHEADER0");
    data[(table + 6) * 4] = b'a';
    data[(table + 7) * 4] = b'b';
    let script = super::super::spt::parse(&data, None)?;
    let targets = script.instructions[1]
        .args
        .iter()
        .find(|arg| arg.name == A::Targets)
        .ok_or(Error::InvalidFormat)?;
    let Value::Group(cases) = &targets.value else {
        return Err(Error::InvalidFormat);
    };
    assert_eq!(cases.len(), 2);
    for (index, target_index) in [(0, 4), (1, 6)] {
        let Value::Group(fields) = &cases[index].value else {
            return Err(Error::InvalidFormat);
        };
        assert!(matches!(fields[0].value,Value::Unsigned(value) if value==index as u64+1));
        assert!(
            matches!(fields[1].value,Value::CodeAddress(target) if target==script.instructions[target_index].span.offset)
        );
        assert_eq!(fields[0].span.size, 4);
        assert_eq!(fields[1].span.size, 0);
    }
    assert!(
        script.instructions[3]
            .args
            .iter()
            .any(|arg| arg.name == A::Value)
    );
    Ok(())
}
