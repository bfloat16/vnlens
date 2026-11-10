//! NNN's text/resource names use the Windows Japanese code page.
use vnlens_core::{Error, Result};
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
