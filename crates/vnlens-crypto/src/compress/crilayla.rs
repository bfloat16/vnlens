//! CRILAYLA: a stored 0x100-byte prefix and reverse MSB-first LZ stream.
//! Reference layout: CRI CPK decompressor, CRILAYLA header size/offset fields.
use super::CompressError;
use std::io::{self, Read};
use vnlens_io::{BinaryReader, BitOrder, StreamBitReader};

struct Reverse<'a>(&'a [u8]);
impl Read for Reverse<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let length = bytes.len().min(self.0.len());
        for byte in &mut bytes[..length] {
            if let Some((last, rest)) = self.0.split_last() {
                *byte = *last;
                self.0 = rest;
            }
        }
        Ok(length)
    }
}

pub fn decompress(data: &[u8], expected: usize) -> Result<Vec<u8>, CompressError> {
    let bad = |pos, reason| CompressError::InvalidData { pos, reason };
    if data.len() < 16 {
        return Err(CompressError::Truncated { pos: data.len() });
    }
    // CRI File System's crifs_tutorial_id.cpk also uses this exact framing
    // with an eight-byte zero tag. Compression is selected by its CPK index.
    if &data[..8] != b"CRILAYLA" && data[..8] != [0; 8] {
        return Err(bad(0, "invalid CRILAYLA signature"));
    }
    let size = BinaryReader::u32_le(&data[8..12]) as usize;
    if size.checked_add(256) != Some(expected) {
        return Err(bad(8, "CRILAYLA output size mismatch"));
    }
    let prefix = (BinaryReader::u32_le(&data[12..16]) as usize)
        .checked_add(16)
        .ok_or_else(|| bad(12, "CRILAYLA prefix offset overflow"))?;
    let end = prefix
        .checked_add(256)
        .ok_or_else(|| bad(prefix, "CRILAYLA prefix end overflow"))?;
    let header = data
        .get(prefix..end)
        .ok_or(CompressError::Truncated { pos: data.len() })?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(expected)
        .map_err(|_| bad(8, "cannot allocate CRILAYLA output"))?;
    output.resize(expected, 0);
    output[..256].copy_from_slice(header);
    let mut bits = StreamBitReader::new(Reverse(&data[16..prefix]), BitOrder::Msb);
    let mut take = |width| {
        bits.read_bits(width)
            .map_err(|_| CompressError::Truncated { pos: prefix })
    };
    let mut position = expected;
    while position > 256 {
        if take(1)? == 0 {
            position -= 1;
            output[position] = take(8)? as u8;
        } else {
            let distance = take(13)? as usize + 3;
            let mut length = 3usize;
            for width in [2, 3, 5, 8] {
                let part = take(width)? as usize;
                length = length
                    .checked_add(part)
                    .ok_or_else(|| bad(position, "CRILAYLA match length overflow"))?;
                if part != (1usize << width) - 1 {
                    break;
                }
                if width == 8 {
                    loop {
                        let part = take(8)? as usize;
                        length = length
                            .checked_add(part)
                            .ok_or_else(|| bad(position, "CRILAYLA match length overflow"))?;
                        if part != 255 {
                            break;
                        }
                    }
                }
            }
            if length > position - 256 {
                return Err(bad(position, "CRILAYLA match exceeds output"));
            }
            for _ in 0..length {
                position -= 1;
                let source = position
                    .checked_add(distance)
                    .filter(|&at| at < expected)
                    .ok_or_else(|| bad(position, "CRILAYLA backreference exceeds decoded data"))?;
                output[position] = output[source];
            }
        }
    }
    Ok(output)
}

#[cfg(test)]
#[path = "../../tests/compress/crilayla.rs"]
mod tests;
