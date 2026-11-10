//! Ring-buffer LZSS decompression.
//!
//! Variant characteristics (shared by several AVG engines):
//! - 4 KiB ring dictionary, write pointer starting at 1;
//! - control byte scanned from the least-significant bit: a set bit is a
//!   literal, a clear bit is a back-reference;
//! - a match uses two bytes `hi lo`: offset = `hi << 4 | lo >> 4`, length =
//!   `2 + (lo & 0x0F)`.

use vnlens_io::BinaryReader;

use super::CompressError;

const FRAME_SIZE: usize = 0x1000;
const FRAME_MASK: usize = FRAME_SIZE - 1;
/// Decompresses LZSS data prefixed with a little-endian `u32` unpacked length.
pub fn decompress_prefixed(input: &[u8]) -> Result<Vec<u8>, CompressError> {
    let mut reader = BinaryReader::new(input);
    let unpacked = reader
        .read_u32_le()
        .map_err(|_| CompressError::Truncated { pos: input.len() })? as usize;
    let body = reader
        .read_bytes(reader.remaining())
        .map_err(|_| CompressError::Truncated { pos: 4 })?;
    decompress(body, unpacked)
}

/// Decompresses `input`, whose unpacked length is known to be `unpacked` bytes.
pub fn decompress(input: &[u8], unpacked: usize) -> Result<Vec<u8>, CompressError> {
    let mut out = Vec::new();
    let mut frame = [0u8; FRAME_SIZE];
    let mut frame_pos: usize = 1;
    let mut src = 0usize;

    while out.len() < unpacked {
        let ctl = *input
            .get(src)
            .ok_or(CompressError::Truncated { pos: src })?;
        src += 1;

        let mut bit = 1u32;
        while out.len() < unpacked && bit != 0x100 {
            if ctl as u32 & bit != 0 {
                // Literal.
                let b = *input
                    .get(src)
                    .ok_or(CompressError::Truncated { pos: src })?;
                src += 1;
                frame[frame_pos & FRAME_MASK] = b;
                frame_pos += 1;
                out.push(b);
            } else {
                // Back-reference.
                let pair = input
                    .get(src..src + 2)
                    .ok_or(CompressError::Truncated { pos: src })?;
                src += 2;
                let hi = pair[0] as usize;
                let lo = pair[1] as usize;
                let match_pos = hi << 4 | lo >> 4;
                let count = 2 + (lo & 0x0F);
                let count = count.min(unpacked - out.len());
                super::copy::ring(&mut frame, &mut frame_pos, match_pos, count, &mut out);
            }
            bit <<= 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "../../tests/compress/lzss.rs"]
mod tests;
