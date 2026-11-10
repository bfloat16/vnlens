//! TextStream.cpp cipher modes 0/1 transform UTF-16LE code units; mode 2 is
//! zlib with u64 stored/decoded byte lengths. The BOM precedes the length fields.
use vnlens_core::{Error, Result};
use vnlens_crypto::compress::zlib;
use vnlens_io::BinaryReader;
fn corrupt(reason: &str) -> Error {
    Error::Corrupt {
        offset: 0,
        reason: reason.into(),
    }
}
pub(super) fn decode(data: &[u8]) -> Result<Option<String>> {
    let mut r = BinaryReader::new(data);
    let mut mode = None;
    let decoded;
    if data.starts_with(&[0xfe, 0xfe]) {
        r.read_bytes(2)?;
        let cipher = r.read_u8()?;
        if r.read_u16_le()? != 0xfeff {
            return Err(corrupt("Missing KiriKiri text BOM"));
        }
        match cipher {
            0 | 1 => mode = Some(cipher),
            2 => {
                let stored = usize::try_from(r.read_u64_le()?)
                    .map_err(|_| corrupt("Text stored size exceeds memory"))?;
                let size = usize::try_from(r.read_u64_le()?)
                    .map_err(|_| corrupt("Text decoded size exceeds memory"))?;
                let bytes = r.read_bytes(stored)?;
                if r.remaining() != 0 {
                    return Err(corrupt("Trailing KiriKiri text data"));
                }
                decoded = zlib::inflate_with_limit(bytes, size)
                    .map_err(|e| corrupt(&format!("KiriKiri text zlib: {e}")))?;
                if decoded.len() != size {
                    return Err(corrupt("KiriKiri text length mismatch"));
                }
                r = BinaryReader::new(&decoded);
            }
            _ => return Err(Error::Unsupported("KiriKiri text cipher mode".into())),
        }
    } else if data.starts_with(&[0xff, 0xfe]) {
        r.read_bytes(2)?;
    } else {
        return Ok(None);
    }
    let mut words = Vec::new();
    while r.remaining() != 0 {
        let mut word = r.read_u16_le()?;
        match mode {
            Some(0) if word >= 0x20 => word ^= ((word & 0xfe) << 8) ^ 1,
            Some(1) => word = ((word & 0xaaaa) >> 1) | ((word & 0x5555) << 1),
            _ => {}
        }
        words.push(word);
    }
    // An inner BOM is emitted by some mode-2 writers.
    let words = if mode.is_none() && words.first() == Some(&0xfeff) {
        &words[1..]
    } else {
        &words
    };
    String::from_utf16(words)
        .map(Some)
        .map_err(|_| corrupt("Invalid KiriKiri text UTF-16"))
}

#[cfg(test)]
#[path = "../../tests/krkr/text.rs"]
mod tests;
