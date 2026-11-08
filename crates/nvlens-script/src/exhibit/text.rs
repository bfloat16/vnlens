//! ExHIBIT RNF/INI text, with native CP932 and unchanged whitespace.
use nvlens_core::Result;
pub(super) fn decode(data: &[u8]) -> Result<Option<String>> {
    let start = data.trim_ascii_start();
    let assignment = start.split(|&b| b == b'\n').next().is_some_and(|line| {
        line.split(|&b| b == b'=').next().is_some_and(|name| {
            line.contains(&b'=')
                && !name.is_empty()
                && name
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b' ' | b'\t'))
        })
    });
    if !(start.starts_with(b";") || start.starts_with(b"[") || assignment)
        || data
            .iter()
            .any(|&b| b < 32 && !matches!(b, b'\r' | b'\n' | b'\t'))
    {
        return Ok(None);
    }
    let (text, _, errors) = encoding_rs::SHIFT_JIS.decode(data);
    Ok((!errors).then(|| text.into_owned()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn configuration_text_keeps_whitespace_and_decodes_cp932() {
        assert_eq!(
            decode(b"  ; \x82\xa0\r\nkey=1\r\n").unwrap().as_deref(),
            Some("  ; あ\r\nkey=1\r\n")
        );
        assert!(decode(b"[\0binary").unwrap().is_none());
    }
}
