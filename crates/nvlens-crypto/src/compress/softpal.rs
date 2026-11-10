//! PAL's PGD LZ stream (Pal::sub_100C5970): LSB-first flags select literal
//! runs or 12-bit backward distances with short/long match lengths.
use super::CompressError;
use nvlens_io::BinaryReader;

pub fn decompress(input: &[u8], size: usize) -> Result<Vec<u8>, CompressError> {
    let mut r = BinaryReader::new(input);
    let mut out = Vec::new();
    while out.len() < size {
        let flags = r
            .read_u8()
            .map_err(|_| CompressError::Truncated { pos: r.position() })?;
        for bit in 0..8 {
            if out.len() == size {
                break;
            }
            let at = r.position();
            if flags & (1 << bit) == 0 {
                let count = r
                    .read_u8()
                    .map_err(|_| CompressError::Truncated { pos: at })?
                    as usize;
                if count > size - out.len() {
                    return Err(CompressError::OutputTooLarge { limit: size });
                }
                out.extend_from_slice(
                    r.read_bytes(count)
                        .map_err(|_| CompressError::Truncated { pos: at })?,
                );
            } else {
                let word = r
                    .read_u16_le()
                    .map_err(|_| CompressError::Truncated { pos: at })?
                    as usize;
                let (distance, count) = if word & 8 != 0 {
                    (word >> 4, (word & 7) + 4)
                } else {
                    let low = r
                        .read_u8()
                        .map_err(|_| CompressError::Truncated { pos: at })?
                        as usize;
                    let code = (word << 8) | low;
                    (code >> 12, (code & 0xfff) + 4)
                };
                if distance == 0 || distance > out.len() {
                    return Err(CompressError::InvalidData {
                        pos: at,
                        reason: "match precedes output history",
                    });
                }
                if count > size - out.len() {
                    return Err(CompressError::OutputTooLarge { limit: size });
                }
                super::copy::append(&mut out, distance, count);
            }
        }
    }
    Ok(out)
}
#[cfg(test)]
#[path = "../../tests/compress/softpal.rs"]
mod tests;
