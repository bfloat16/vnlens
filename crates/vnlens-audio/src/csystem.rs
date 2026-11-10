//! C,system Tink Ogg envelope, native sub_4B9FF0. The initial 0xe1f logical
//! bytes use a copyright-string XOR stream; later cycles start at key byte 1.
use std::borrow::Cow;
use vnlens_core::{Error, Result};

/// Restores the standard Ogg resource. The optional 12-byte music prefix is
/// removed when followed by Tink or a standard Ogg/WAV header. Unencrypted
/// audio borrows its logical payload, including after removal of that prefix.
pub fn decode_envelope<'a>(data: &'a [u8], key: &[u8]) -> Result<Cow<'a, [u8]>> {
    let data = if matches!(data.get(12..16), Some(b"Tink" | b"OggS"))
        || data.get(12..16) == Some(b"RIFF") && data.get(20..24) == Some(b"WAVE")
    {
        &data[12..]
    } else {
        data
    };
    if !data.starts_with(b"Tink") {
        return Ok(Cow::Borrowed(data));
    }
    if key.len() < 2 {
        return Err(Error::UnknownScheme(Some(
            "C,system audio key is missing".into(),
        )));
    }
    let mut out = data.to_vec();
    out[..4].copy_from_slice(b"OggS");
    let end = out.len().min(0xe1f);
    let mut at = 4;
    let mut k = 0;
    while at < end {
        let count = (end - at).min(key.len() - k);
        vnlens_crypto::cipher::xor::apply(&mut out[at..at + count], &key[k..k + count])
            .map_err(|e| Error::Unsupported(format!("C,system audio XOR: {e}")))?;
        at += count;
        k = 1;
    }
    Ok(Cow::Owned(out))
}
#[cfg(test)]
#[path = "../tests/csystem.rs"]
mod tests;
