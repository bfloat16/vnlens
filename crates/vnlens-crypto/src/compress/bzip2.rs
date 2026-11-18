//! bzip2 stream decoding, including its block and stream CRC checks. The
//! expected size belongs to the caller's format, rather than a global limit.
use std::io::{self, Read};

/// Decodes a complete stream of exactly `size` bytes. Truncation retains
/// UnexpectedEof; an overlong output or CRC error is InvalidData.
pub fn decompress(input: &[u8], size: usize) -> io::Result<Vec<u8>> {
    let mut decoder = bzip2::read::BzDecoder::new(input);
    let mut out = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let count = decoder.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        if count > size - out.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bzip2 output exceeds declared size",
            ));
        }
        out.extend_from_slice(&chunk[..count]);
    }
    if out.len() != size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bzip2 output size mismatch",
        ));
    }
    Ok(out)
}

#[cfg(test)]
#[path = "../../tests/compress/bzip2.rs"]
mod tests;
