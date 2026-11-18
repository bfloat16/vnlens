use super::*;

#[test]
fn encrypted_and_plain_source_routes_preserve_text() -> Result<()> {
    let source = b";test\r\n*define\r\ncaption \"\x90\x85\x90\x46\"\r\ngame\r\n*start\r\nend\r\n";
    for (tag, key) in [
        ("nscript/nscripter", 0x84),
        ("zat/nscripter", 0x6f),
        ("text/nscripter", 0),
    ] {
        let encoded: Vec<u8> = source.iter().map(|&b| b ^ key).collect();
        let decoded = crate::decode_as(tag, &encoded, &ArchiveOptions::default())?;
        assert_eq!(decoded.as_ref(), source);
        assert!(crate::decode_text_as(tag, &decoded)?.is_some_and(|text| text.contains("水色")));
        assert!(crate::disassemble_as(tag, &decoded, None)?.is_none());
    }
    assert!(crate::decode_text_as("text/nscripter", &[0x81]).is_err());
    Ok(())
}
