//! ExHIBIT GYU compression: Okumura LZSS and an interleaved MSB LZ stream.
//! Layout follows GARbro GyuReader, checked against Ux image readers.

use std::io;
use vnlens_io::{BinaryIo, BinaryReader, BitOrder, BitReader};

pub fn lzss(input: &[u8], size: usize) -> io::Result<Vec<u8>> {
    let mut r = BinaryReader::new(input);
    let mut ring = [0; 4096];
    let mut position = 0xfee;
    let mut out = Vec::new();
    while out.len() < size {
        let flags = r.read_u8()?;
        for bit in 0..8 {
            if out.len() == size {
                break;
            }
            if flags & (1 << bit) != 0 {
                let byte = r.read_u8()?;
                ring[position] = byte;
                position = (position + 1) & 4095;
                out.push(byte);
            } else {
                let word = usize::from(r.read_u16_le()?);
                let source = (word & 255) | ((word >> 4) & 0xf00);
                let count = ((word >> 8) & 15) + 3;
                if count > size - out.len() {
                    return Err(BinaryIo::invalid_input("GYU LZSS match exceeds image"));
                }
                super::copy::ring(&mut ring, &mut position, source, count, &mut out);
            }
        }
    }
    Ok(out)
}

pub fn gyu(input: &[u8], size: usize) -> io::Result<Vec<u8>> {
    let mut header = BinaryReader::new(input);
    header.read_u32_le()?;
    let mut bits = BitReader::new(header.read_bytes(header.remaining())?, BitOrder::Msb);
    let mut out = Vec::new();
    if size != 0 {
        out.push(bits.read_raw_bytes(1)?[0]);
    }
    while out.len() < size {
        if bits.read_bit()? != 0 {
            out.push(bits.read_raw_bytes(1)?[0]);
            continue;
        }
        let (distance, count) = if bits.read_bit()? != 0 {
            let word = usize::from(BinaryReader::u16_be(bits.read_raw_bytes(2)?));
            let count = if word & 7 != 0 {
                (word & 7) + 2
            } else {
                let count = usize::from(bits.read_raw_bytes(1)?[0]);
                if count == 0 {
                    return Err(BinaryIo::unexpected_eof("GYU stream ended before image"));
                }
                count + 1
            };
            (8192 - (word >> 3), count)
        } else {
            let count = bits.read_bits(2)? as usize + 2;
            (256 - usize::from(bits.read_raw_bytes(1)?[0]), count)
        };
        if distance > out.len() || count > size - out.len() {
            return Err(BinaryIo::invalid_input(
                "GYU match exceeds image history or dimensions",
            ));
        }
        super::copy::append(&mut out, distance, count);
    }
    Ok(out)
}

#[cfg(test)]
#[path = "../../tests/compress/exhibit.rs"]
mod tests;
