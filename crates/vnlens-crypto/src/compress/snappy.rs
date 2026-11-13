//! Snappy raw blocks: u32 base-128 output length, then literal/copy tags.
//! Layout follows Snappy's format_description.txt and RawUncompress; YSSnp
//! exports use this unframed stream (YSSnp_Uncompress, sub_10001170).

use super::{CompressError, copy};
use vnlens_io::BinaryReader;

/// Decodes one complete raw block. The declared output length bounds every
/// literal and overlapping copy; trailing or truncated input is rejected.
pub fn decode(data: &[u8], expected: usize) -> Result<Vec<u8>, CompressError> {
    let mut output = Vec::new();
    process(data, expected, Some(&mut output))?;
    Ok(output)
}

/// Validates the complete raw block without allocating or expanding literals
/// and copies. This is structural evidence for a container's codec variant.
pub fn validate(data: &[u8], expected: usize) -> Result<(), CompressError> {
    process(data, expected, None)
}

fn process(
    data: &[u8],
    expected: usize,
    mut output: Option<&mut Vec<u8>>,
) -> Result<(), CompressError> {
    let mut reader = BinaryReader::new(data);
    let length = reader
        .read_uleb32()
        .map_err(|_| invalid(0, "Invalid Snappy output length"))? as usize;
    if length != expected {
        return Err(invalid(0, "Snappy output length mismatch"));
    }
    let mut produced = 0usize;
    while reader.remaining() != 0 {
        let at = reader.position();
        let tag = reader
            .read_u8()
            .map_err(|_| invalid(at, "Truncated Snappy tag"))?;
        let (count, distance) = match tag & 3 {
            0 => {
                let code = tag >> 2;
                let count = if code < 60 {
                    usize::from(code) + 1
                } else {
                    let width = code - 59;
                    let value = reader
                        .read_compact_u64(width, vnlens_io::Endian::Little)
                        .map_err(|_| invalid(at, "Truncated Snappy literal length"))?;
                    usize::try_from(value)
                        .ok()
                        .and_then(|value| value.checked_add(1))
                        .ok_or_else(|| invalid(at, "Snappy literal length overflow"))?
                };
                (count, None)
            }
            1 => {
                let low = reader
                    .read_u8()
                    .map_err(|_| invalid(at, "Truncated Snappy copy offset"))?;
                (
                    usize::from((tag >> 2) & 7) + 4,
                    Some(usize::from(tag & 0xe0) * 8 + usize::from(low)),
                )
            }
            2 => (
                usize::from(tag >> 2) + 1,
                Some(usize::from(
                    reader
                        .read_u16_le()
                        .map_err(|_| invalid(at, "Truncated Snappy copy offset"))?,
                )),
            ),
            _ => (
                usize::from(tag >> 2) + 1,
                Some(
                    reader
                        .read_u32_le()
                        .map_err(|_| invalid(at, "Truncated Snappy copy offset"))?
                        as usize,
                ),
            ),
        };
        if produced.checked_add(count).is_none_or(|end| end > length) {
            return Err(invalid(at, "Snappy tag exceeds output length"));
        }
        if let Some(distance) = distance {
            if distance == 0 || distance > produced {
                return Err(invalid(at, "Snappy copy precedes output"));
            }
            if let Some(output) = output.as_deref_mut() {
                copy::append(output, distance, count);
            }
        } else {
            let literal = reader
                .read_bytes(count)
                .map_err(|_| invalid(at, "Truncated Snappy literal"))?;
            if let Some(output) = output.as_deref_mut() {
                output.extend_from_slice(literal);
            }
        }
        produced += count;
    }
    if produced != length {
        return Err(invalid(reader.position(), "Truncated Snappy output"));
    }
    Ok(())
}

fn invalid(pos: usize, reason: &'static str) -> CompressError {
    CompressError::InvalidData { pos, reason }
}

#[cfg(test)]
#[path = "../../tests/compress/snappy.rs"]
mod tests;
