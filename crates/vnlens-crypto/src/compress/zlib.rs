//! zlib (RFC 1950) inflate, wrapping `flate2`.

use std::io::Read;
use vnlens_io::BinaryReader;

pub use flate2::read::ZlibDecoder;

use super::CompressError;

/// Checks the RFC 1950 CMF/FLG fields without decoding the stream. A valid
/// header does not establish valid deflate data or the trailing checksum.
#[must_use]
pub fn has_header(data: &[u8]) -> bool {
    let Some(header) = data.get(..2) else {
        return false;
    };
    header[0] & 15 == 8 && header[0] >> 4 <= 7 && BinaryReader::u16_be(header).is_multiple_of(31)
}

/// Validates deflate termination, Adler32 and the caller's format-defined
/// output length with bounded scratch memory, without retaining decoded bytes.
pub fn validate(data: &[u8], expected: usize) -> Result<(), CompressError> {
    let mut decoder = flate2::Decompress::new(true);
    let mut buffer = [0; 8192];
    loop {
        let input = decoder.total_in();
        let output = decoder.total_out();
        let start = usize::try_from(input).map_err(|_| CompressError::Inflate)?;
        let remaining = data.get(start..).ok_or(CompressError::Inflate)?;
        let status = decoder
            .decompress(remaining, &mut buffer, flate2::FlushDecompress::None)
            .map_err(|_| CompressError::Inflate)?;
        if decoder.total_out() > expected as u64 {
            return Err(CompressError::OutputTooLarge { limit: expected });
        }
        if status == flate2::Status::StreamEnd {
            return if decoder.total_out() == expected as u64 {
                Ok(())
            } else {
                Err(CompressError::Inflate)
            };
        }
        if decoder.total_in() == input && decoder.total_out() == output {
            return Err(CompressError::Inflate);
        }
    }
}

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
#[path = "../../tests/compress/zlib.rs"]
mod tests;
