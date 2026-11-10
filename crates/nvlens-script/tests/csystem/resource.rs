use super::*;
use nvlens_io::BinaryWriter;

fn words(values: &[u32]) -> Vec<u8> {
    let mut bytes = vec![0; values.len() * 4];
    for (word, &value) in bytes.chunks_exact_mut(4).zip(values) {
        BinaryWriter::u32_le(value, word);
    }
    bytes
}
#[test]
fn composition_tables_preserve_ids_signed_fields_and_spans() -> Result<()> {
    let data = words(&[
        1,
        710000016,
        0,
        1,
        12,
        13,
        0,
        1,
        0,
        763,
        47,
        u32::MAX,
        1,
        0,
        0,
        0,
    ]);
    let script = crate::disassemble_as("f0/csystem", &data, None)?.ok_or(Error::InvalidFormat)?;
    assert_eq!(script.sections[0].raw, data);
    assert_eq!(script.instructions[0].span.size, data.len() as u64);
    let json = String::from_utf8(script.to_json()?).map_err(|_| Error::InvalidFormat)?;
    assert!(json.contains("710000016") && json.contains("-1"));
    for end in 0..data.len() {
        assert!(crate::disassemble_as("f0/csystem", &data[..end], None).is_err());
    }
    Ok(())
}
#[test]
fn typed_property_strings_and_animation_are_distinct() -> Result<()> {
    let mut data = words(&[1]);
    data.extend([b'n', 0]);
    data.extend(words(&[1, 1]));
    data.extend([b'p', 0]);
    data.extend(words(&[2, 1, 1]));
    data.extend([b'x', 0]);
    data.extend(words(&[3, u32::MAX]));
    let script =
        crate::disassemble_as("properties/csystem", &data, None)?.ok_or(Error::InvalidFormat)?;
    assert_eq!(script.instructions.len(), 2);
    assert!(crate::disassemble_as("animation/csystem", &data, None).is_err());
    for end in 0..data.len() {
        assert!(crate::disassemble_as("properties/csystem", &data[..end], None).is_err());
    }
    let frames = words(&[2, 700000000, 200, 700000001, 300]);
    assert!(crate::disassemble_as("animation/csystem", &frames, None)?.is_some());
    Ok(())
}

#[test]
fn legacy_buttons_have_no_extension_and_nine_final_settings() -> Result<()> {
    let mut values = vec![7, 0, 0, 0, 1];
    values.extend([0; 17]);
    values.extend([0; 11]);
    let bytes = words(&values);
    let mut options = nvlens_core::ArchiveOptions::default();
    options.numbers.insert("csystem_legacy", 1);
    let script = crate::disassemble_with_options_as("e0/csystem", &bytes, None, &options)?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(script.instructions.len(), 3);
    assert_eq!(script.instructions[1].span.size, 68);
    assert_eq!(script.sections[0].raw, bytes);
    assert!(crate::disassemble_as("e0/csystem", &bytes, None).is_err());
    for end in 0..bytes.len() {
        assert!(
            crate::disassemble_with_options_as("e0/csystem", &bytes[..end], None, &options)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn legacy_animation_uses_word_pairs_and_preserves_markers() -> Result<()> {
    let mut bytes = Vec::new();
    for value in [1, 201, 1, 10, 9, 218, 201, 1, 246] {
        let mut word = [0; 2];
        BinaryWriter::u16_le(value, &mut word);
        bytes.extend(word);
    }
    let script = crate::disassemble_as("animation-legacy/csystem", &bytes, None)?
        .ok_or(Error::InvalidFormat)?;
    assert_eq!(script.instructions.len(), 2);
    assert!(matches!(
        script.instructions[1].args[1].value,
        Value::Unsigned(2504)
    ));
    assert!(matches!(
        script.instructions[1].args[3].value,
        Value::Unsigned(500)
    ));
    assert_eq!(script.sections[0].raw, bytes);
    for end in 0..bytes.len() {
        assert!(crate::disassemble_as("animation-legacy/csystem", &bytes[..end], None).is_err());
    }
    Ok(())
}
