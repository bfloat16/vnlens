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
                let mut offset = usize::from(pair & 4095);
                let mut length = usize::from(pair >> 12) + 3;
                if length == 18 {
                    length += usize::from(r.read_u8()?);
                }
                if length > size - out.len() {
                    return Err(BinaryIo::invalid_input("TLG match exceeds plane"));
                }
                for _ in 0..length {
                    let value = self.dictionary[offset];
                    offset = (offset + 1) & 4095;
                    out.push(value);
                    self.dictionary[self.position] = value;
                    self.position = (self.position + 1) & 4095;
                }
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
mod tests {
    use super::*;
    #[test]
    fn overlap_extended_lengths_and_dictionary_persistence() -> io::Result<()> {
        let mut slide = Slide::default();
        assert_eq!(slide.decode(&[8, b'A', b'B', b'C', 0, 0], 6)?, b"ABCABC");
        assert_eq!(slide.decode(&[1, 3, 0], 3)?, b"ABC");
        assert_eq!(Slide::default().decode(&[1, 0, 0xf0, 0], 18)?, [0; 18]);
        assert!(Slide::default().decode(&[1, 0, 0xf0], 18).is_err());
        assert!(Slide::default().decode(&[1, 0, 0xf0, 0], 17).is_err());
        Ok(())
    }
}
