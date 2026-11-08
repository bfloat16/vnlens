//! TextStream.cpp cipher modes 0/1 transform UTF-16LE code units; mode 2 is
//! zlib with u64 stored/decoded byte lengths. The BOM precedes the length fields.
use nvlens_core::{Error, Result};
use nvlens_crypto::compress::zlib;
use nvlens_io::BinaryReader;
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
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;
    use std::io::Write;
    #[test]
    fn all_text_modes_preserve_unicode_and_check_lengths() -> Result<()> {
        let text = "hello 日本語😀\r\n";
        let mut plain = vec![0; text.encode_utf16().count() * 2];
        for (w, b) in text.encode_utf16().zip(plain.as_chunks_mut::<2>().0) {
            BinaryWriter::u16_le(w, b);
        }
        for mode in [0, 1] {
            let mut data = vec![0xfe, 0xfe, mode, 0xff, 0xfe];
            for w in text.encode_utf16() {
                let value = if mode == 0 && w >= 32 {
                    w ^ (((w ^ 1) & 0xfe) << 8) ^ 1
                } else if mode == 1 {
                    ((w & 0xaaaa) >> 1) | ((w & 0x5555) << 1)
                } else {
                    w
                };
                let mut bytes = [0; 2];
                BinaryWriter::u16_le(value, &mut bytes);
                data.extend(bytes);
            }
            assert_eq!(decode(&data)?.as_deref(), Some(text));
            data.pop();
            assert!(matches!(decode(&data), Err(Error::Io(_))));
        }
        let mut zip = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zip.write_all(&plain)?;
        let zip = zip.finish()?;
        let mut data = vec![0xfe, 0xfe, 2, 0xff, 0xfe];
        data.resize(21, 0);
        BinaryWriter::u64_le(zip.len() as u64, &mut data[5..]);
        BinaryWriter::u64_le(plain.len() as u64, &mut data[13..]);
        data.extend(zip);
        assert_eq!(decode(&data)?.as_deref(), Some(text));
        BinaryWriter::u64_le(1, &mut data[13..]);
        assert!(decode(&data).is_err());
        Ok(())
    }
}
