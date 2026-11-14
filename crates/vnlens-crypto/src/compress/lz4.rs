//! Raw LZ4 blocks: token literal/match lengths, little-endian distances and
//! overlapping back references, as specified by the LZ4 block format.
use std::io;
use vnlens_io::BinaryReader;

/// Decodes one complete block to its format-declared logical size.
pub fn decompress(input: &[u8], size: usize) -> io::Result<Vec<u8>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "Invalid LZ4 block");
    let mut reader = BinaryReader::new(input);
    let mut output = Vec::new();
    while reader.position() < input.len() {
        let token = reader.read_u8()?;
        let literals = length(&mut reader, usize::from(token >> 4))?;
        if literals > size.saturating_sub(output.len()) {
            return Err(invalid());
        }
        output.extend_from_slice(reader.read_bytes(literals)?);
        if reader.position() == input.len() {
            break;
        }
        let distance = usize::from(reader.read_u16_le()?);
        let count = length(&mut reader, usize::from(token & 15))?
            .checked_add(4)
            .ok_or_else(invalid)?;
        if distance == 0 || distance > output.len() || count > size.saturating_sub(output.len()) {
            return Err(invalid());
        }
        super::copy::append(&mut output, distance, count);
    }
    if output.len() != size {
        return Err(invalid());
    }
    Ok(output)
}

fn length(reader: &mut BinaryReader<'_>, mut value: usize) -> io::Result<usize> {
    if value == 15 {
        loop {
            let extra = reader.read_u8()?;
            value = value
                .checked_add(usize::from(extra))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "LZ4 length overflow"))?;
            if extra != 255 {
                break;
            }
        }
    }
    Ok(value)
}

#[cfg(test)]
#[path = "../../tests/compress/lz4.rs"]
mod tests;
