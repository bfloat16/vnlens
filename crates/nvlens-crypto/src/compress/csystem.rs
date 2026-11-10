//! C,system's Okumura LZSS (sub_422A90): zeroed 4096-byte dictionary,
//! initial cursor 0xfee, LSB-first literal flags and 12-bit absolute matches.
use super::CompressError;
use nvlens_io::BinaryReader;

pub fn decompress(input: &[u8], size: usize) -> Result<Vec<u8>, CompressError> {
    let mut r = BinaryReader::new(input);
    let mut out = Vec::new();
    let mut dictionary = [0; 4096];
    let mut position = 0xfee;
    while out.len() < size {
        let flags = r
            .read_u8()
            .map_err(|_| CompressError::Truncated { pos: r.position() })?;
        for bit in 0..8 {
            if out.len() == size {
                break;
            }
            let at = r.position();
            if flags & (1 << bit) != 0 {
                let byte = r
                    .read_u8()
                    .map_err(|_| CompressError::Truncated { pos: at })?;
                dictionary[position] = byte;
                position = (position + 1) & 4095;
                out.push(byte);
            } else {
                let code = r
                    .read_u16_le()
                    .map_err(|_| CompressError::Truncated { pos: at })?
                    as usize;
                let count = ((code >> 8) & 15) + 3;
                if count > size - out.len() {
                    return Err(CompressError::OutputTooLarge { limit: size });
                }
                let source = (code & 255) | ((code >> 4) & 0xf00);
                super::copy::ring(&mut dictionary, &mut position, source, count, &mut out);
            }
        }
    }
    Ok(out)
}
#[cfg(test)]
#[path = "../../tests/compress/csystem.rs"]
mod tests;
