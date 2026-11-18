//! NScripter 2.82 sub_4447A0: MSB bit LZSS, 256-byte history, cursor 239,
//! length nibble + 2. sub_445550: three SPB byte planes, four differences per
//! control, alternating row direction. Integer framing belongs to the archive.
use std::io;
use vnlens_io::{BinaryIo, BitOrder, BitReader};

/// Decodes exactly the index-declared length. A truncated token is an EOF;
/// a match crossing the declared boundary is invalid compressed data.
pub fn lzss(input: &[u8], size: usize) -> io::Result<Vec<u8>> {
    let mut bits = BitReader::new(input, BitOrder::Msb);
    let mut dictionary = [0; 256];
    dictionary[..239].fill(b' ');
    let mut cursor = 239;
    let mut out = Vec::new();
    while out.len() < size {
        if bits.read_bit()? != 0 {
            let byte = bits.read_bits(8)? as u8;
            dictionary[cursor] = byte;
            cursor = (cursor + 1) & 255;
            out.push(byte);
        } else {
            let source = bits.read_bits(8)? as usize;
            let count = bits.read_bits(4)? as usize + 2;
            if count > size - out.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NScripter LZSS match exceeds declared size",
                ));
            }
            for i in 0..count {
                let byte = dictionary[(source + i) & 255];
                dictionary[cursor] = byte;
                cursor = (cursor + 1) & 255;
                out.push(byte);
            }
        }
    }
    Ok(out)
}

/// Decodes SPB planes into tightly packed, top-down BGR24 pixels. Width and
/// height are the format's nonzero u16 dimensions. Final four-value groups
/// are consumed completely, including values past the last pixel.
pub fn spb(input: &[u8], width: u16, height: u16) -> io::Result<Vec<u8>> {
    if width == 0 || height == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SPB has zero dimensions",
        ));
    }
    let width = usize::from(width);
    let count = width * usize::from(height);
    let size = count
        .checked_mul(3)
        .ok_or_else(|| BinaryIo::invalid_input("SPB dimensions exceed address space"))?;
    let mut out = vec![0; size];
    let mut bits = BitReader::new(input, BitOrder::Msb);
    for channel in 0..3 {
        let mut value = bits.read_bits(8)? as u8;
        out[channel] = value;
        let mut pixel = 1;
        while pixel < count {
            let control = bits.read_bits(3)? as u8;
            let width_bits = match control {
                0 => 0,
                7 => bits.read_bit()? + 1,
                other => other + 2,
            };
            for _ in 0..4 {
                if width_bits != 0 {
                    let code = bits.read_bits(width_bits)? as u8;
                    value = if width_bits == 8 {
                        code
                    } else if code & 1 != 0 {
                        value.wrapping_add((code >> 1) + 1)
                    } else {
                        value.wrapping_sub(code >> 1)
                    };
                }
                if pixel < count {
                    let y = pixel / width;
                    let x = pixel % width;
                    let x = if y & 1 == 0 { x } else { width - 1 - x };
                    out[(y * width + x) * 3 + channel] = value;
                }
                pixel += 1;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "../../tests/compress/nscripter.rs"]
mod tests;
