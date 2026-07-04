//! Ring-buffer LZSS decompression.
//!
//! Variant characteristics (shared by several AVG engines):
//! - 4 KiB ring dictionary, write pointer starting at 1;
//! - control byte scanned from the least-significant bit: a set bit is a
//!   literal, a clear bit is a back-reference;
//! - a match uses two bytes `hi lo`: offset = `hi << 4 | lo >> 4`, length =
//!   `2 + (lo & 0x0F)`.

use nvlens_io::BinaryReader;

use super::CompressError;

const FRAME_SIZE: usize = 0x1000;
const FRAME_MASK: usize = FRAME_SIZE - 1;
/// Initial preallocation cap, to keep a corrupt header from triggering a huge
/// allocation; the buffer grows on demand if this is not enough.
const MAX_PREALLOC: usize = 1 << 24;

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
    let mut out = Vec::with_capacity(unpacked.min(MAX_PREALLOC));
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
                for i in 0..count {
                    if out.len() >= unpacked {
                        break;
                    }
                    let v = frame[(match_pos + i) & FRAME_MASK];
                    frame[frame_pos & FRAME_MASK] = v;
                    frame_pos += 1;
                    out.push(v);
                }
            }
            bit <<= 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn all_literals_roundtrip() {
        // One control byte covering eight literals, all bits set.
        let mut packed = vec![0xFFu8];
        packed.extend_from_slice(b"ABCDEFGH");
        let out = decompress(&packed, 8).unwrap();
        assert_eq!(&out, b"ABCDEFGH");
    }

    #[test]
    fn back_reference_repeats() {
        // Write 'A', then copy it via one back-reference.
        // Control byte: bit0=1 literal 'A'; bit1=0 match.
        // 'A' goes to frame[1], write pointer -> 2. Match offset=1 (reads
        // frame[1]='A'), length = 2 + 3 = 5.
        let hi = 0x00u8;
        let lo = 0x13u8; // offset low nibble = 1 -> offset = 1; length = 2 + 3 = 5
        let packed = vec![0b0000_0001, b'A', hi, lo];
        let out = decompress(&packed, 6).unwrap();
        assert_eq!(&out, b"AAAAAA");
    }

    #[test]
    fn truncated_input_errors() {
        let packed = vec![0xFF, b'A'];
        assert!(matches!(
            decompress(&packed, 8),
            Err(CompressError::Truncated { .. })
        ));
    }
}
