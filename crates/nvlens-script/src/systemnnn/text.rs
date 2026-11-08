//! NNN's text/resource names use the Windows Japanese code page.
use nvlens_core::{Error, Result};
pub(super) fn decode(data: &[u8]) -> Result<String> {
    let (text, _, errors) = encoding_rs::SHIFT_JIS.decode(data);
    if errors {
        return Err(Error::Corrupt {
            offset: 0,
            reason: "Invalid SystemNNN CP932 text".into(),
        });
    }
    Ok(text.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScriptFormat;
    #[test]
    fn cp932_and_inverted_configuration_preserve_text() -> Result<()> {
        let plain = b"name \x82\xa0\r\n";
        assert_eq!(decode(plain)?, "name あ\r\n");
        assert!(decode(b"\x81").is_err());
        let mut encrypted = plain.to_vec();
        nvlens_crypto::cipher::xor::apply_u32_key(&mut encrypted, &[255; 4]);
        assert_eq!(
            super::super::Fxf
                .decode(&encrypted, &Default::default())?
                .as_ref(),
            plain
        );
        assert_eq!(decode(b"")?, "");
        Ok(())
    }
}
