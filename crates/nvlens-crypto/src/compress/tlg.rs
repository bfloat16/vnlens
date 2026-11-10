//! TLG SlideCompressor: LSB-first flags (one = match), 12-bit LE dictionary
//! positions, four-bit lengths + 3, with an extra byte when length is 18.
//! Its zeroed 4096-byte dictionary persists across compressed planes/blocks.
use nvlens_io::{BinaryIo, BinaryReader};
use std::io;
#[derive(Debug)]
pub struct Slide {
    dictionary: [u8; 4096],
    position: usize,
}
impl Default for Slide {
    fn default() -> Self {
        Self {
            dictionary: [0; 4096],
            position: 0,
        }
    }
}
impl Slide {
    /// Creates a decoder with the format's initial dictionary and cursor zero.
    #[must_use]
    pub fn with_dictionary(dictionary: [u8; 4096]) -> Self {
        Self {
            dictionary,
            position: 0,
        }
    }
    /// Decodes exactly the plane size supplied by its image dimensions.
    /// Truncation, excess output and trailing tokens are errors.
    pub fn decode(&mut self, bytes: &[u8], size: usize) -> io::Result<Vec<u8>> {
        let mut r = BinaryReader::new(bytes);
        let mut out = Vec::new();
        let mut flags = 0u8;
        let mut mask = 0u8;
        while out.len() < size {
            if mask == 0 {
                flags = r.read_u8()?;
                mask = 1;
            }
            if flags & mask == 0 {
                let value = r.read_u8()?;
                out.push(value);
                self.dictionary[self.position] = value;
                self.position = (self.position + 1) & 4095;
            } else {
                let pair = r.read_u16_le()?;
                let offset = usize::from(pair & 4095);
                let mut length = usize::from(pair >> 12) + 3;
                if length == 18 {
                    length += usize::from(r.read_u8()?);
                }
                if length > size - out.len() {
                    return Err(BinaryIo::invalid_input("TLG match exceeds plane"));
                }
                super::copy::ring(
                    &mut self.dictionary,
                    &mut self.position,
                    offset,
                    length,
                    &mut out,
                );
            }
            mask = mask.wrapping_shl(1);
        }
        if r.remaining() != 0 {
            return Err(BinaryIo::invalid_input("Trailing TLG slide tokens"));
        }
        Ok(out)
    }
}

#[cfg(test)]
#[path = "../../tests/compress/tlg.rs"]
mod tests;
