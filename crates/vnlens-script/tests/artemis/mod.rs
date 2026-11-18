use super::*;

#[test]
fn utf8_source_is_preserved_and_selected_explicitly() -> Result<()> {
    let data = "*start\r\n[text value=\"日本語\"]\r\n".as_bytes();
    assert_eq!(
        crate::decode_text_as("text/artemis", data)?,
        Some(
            std::str::from_utf8(data)
                .map_err(|_| Error::InvalidFormat)?
                .into()
        )
    );
    assert!(crate::disassemble_as("text/artemis", data, None)?.is_none());
    assert!(matches!(
        crate::decode_text_as("text/artemis", &[0xff]),
        Err(Error::Corrupt { .. })
    ));
    assert!(matches!(
        crate::decode_text_as("unregistered/artemis", data),
        Err(Error::Unsupported(_))
    ));
    Ok(())
}
