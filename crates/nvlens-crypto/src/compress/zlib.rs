//! zlib (RFC 1950) inflate, wrapping `flate2`.

use std::io::Read;

use flate2::read::ZlibDecoder;

use super::CompressError;

/// Opens a streaming zlib decoder. Reads produce only the requested output.
#[must_use]
pub fn decoder<R: Read>(reader: R) -> ZlibDecoder<R> {
    ZlibDecoder::new(reader)
}

/// Inflates a zlib stream. Returns [`CompressError::Inflate`] on any decode
/// error, so callers probing an uncertain key (which yields non-zlib bytes) can
/// reject it via `?`/`.ok()` rather than panicking.
pub fn inflate(data: &[u8]) -> Result<Vec<u8>, CompressError> {
    inflate_with_limit(data, usize::MAX)
}

/// Inflates a zlib stream, failing if the output grows beyond `limit`.
pub fn inflate_with_limit(data: &[u8], limit: usize) -> Result<Vec<u8>, CompressError> {
    let mut out = Vec::new();
    read_limited(ZlibDecoder::new(data), &mut out, limit)?;
    Ok(out)
}

fn read_limited<R: Read>(
    mut reader: R,
    out: &mut Vec<u8>,
    limit: usize,
) -> Result<(), CompressError> {
    let mut chunk = [0u8; 8192];
    loop {
        let read = reader
            .read(&mut chunk)
            .map_err(|_| CompressError::Inflate)?;
        if read == 0 {
            return Ok(());
        }
        let next_len = out
            .len()
            .checked_add(read)
            .ok_or(CompressError::OutputTooLarge { limit })?;
        if next_len > limit {
            return Err(CompressError::OutputTooLarge { limit });
        }
        out.extend_from_slice(&chunk[..read]);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn known_zlib_vector_and_declared_length() {
        let input = [120, 156, 203, 72, 205, 201, 201, 7, 0, 6, 44, 2, 21];
        assert_eq!(inflate_with_limit(&input, 5).unwrap(), b"hello");
        assert!(matches!(
            inflate_with_limit(&input, 4),
            Err(CompressError::OutputTooLarge { .. })
        ));
        let mut damaged = input;
        damaged[12] ^= 1;
        assert!(inflate(&damaged).is_err());
    }
}
