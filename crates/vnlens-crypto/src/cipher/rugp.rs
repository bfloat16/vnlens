//! rUGP encrypted chunks (CPmArchive::SerializeCryptBuffer) and ICI
//! transposition, verified against UnivUI's readers at 10028790/10015870.
//! Chunk lengths and checksums are little endian; every portion, including
//! the final short portion, has a weighted 16-bit checksum.

use std::io;
use vnlens_io::{BinaryIo, BinaryReader};

/// Decodes one framed chunk, advancing only across that chunk. The caller
/// supplies the format's key; neither errors nor Debug expose it.
pub fn decrypt_chunk(reader: &mut BinaryReader<'_>, mut key: u32) -> io::Result<Vec<u8>> {
    let length = !(reader.read_u32_le()? ^ 0xc92e_568b);
    let check = (reader.read_u32_le()? ^ 0xc92e_568f) >> 3;
    if length != check {
        return Err(BinaryIo::invalid_input("RIO encrypted length mismatch"));
    }
    let length = length as usize;
    let stored = length
        .checked_add(length.div_ceil(32) * 2)
        .ok_or_else(|| BinaryIo::invalid_input("RIO encrypted length overflow"))?;
    let mut input = BinaryReader::new(reader.read_bytes(stored)?);
    let mut output = Vec::with_capacity(length);
    while output.len() < length {
        let count = (length - output.len()).min(32);
        let mut checksum = 0u16;
        for weight in (1..=count).rev() {
            let byte = input.read_u8()? ^ key as u8;
            output.push(byte);
            checksum = checksum.wrapping_add(u16::from(byte) * weight as u16);
            key = !key
                .wrapping_mul(2)
                .wrapping_add((key >> 15) & 1)
                .wrapping_add(0xa3b3_76c9);
        }
        if input.read_u16_le()? != checksum {
            return Err(BinaryIo::invalid_input("RIO encrypted checksum mismatch"));
        }
    }
    Ok(output)
}

/// Reverses the ICI byte permutations after the framed cipher is removed.
#[must_use]
pub fn decode_ici(input: &[u8]) -> Vec<u8> {
    fn interleave(input: &[u8], output: &mut [u8], columns: usize) {
        let rows = input.len() / columns;
        for (row, chunk) in output[..rows * columns]
            .chunks_exact_mut(columns)
            .enumerate()
        {
            for (column, byte) in chunk.iter_mut().enumerate() {
                *byte = input[column * rows + row];
            }
        }
        output[rows * columns..].copy_from_slice(&input[rows * columns..]);
    }
    let mut output = vec![0; input.len()];
    interleave(input, &mut output, 6);
    let mut previous = 0u8;
    for byte in &mut output {
        let original = *byte;
        *byte = byte.wrapping_sub(previous) ^ 0xa5;
        previous = original;
    }
    let mut intermediate = vec![0; input.len()];
    interleave(&output, &mut intermediate, 5);
    previous = 0;
    for byte in intermediate.iter_mut().rev() {
        let original = *byte;
        *byte = byte.wrapping_sub(previous);
        previous = original;
    }
    interleave(&intermediate, &mut output, 3);
    for chunk in output.as_chunks_mut::<3>().0 {
        for (byte, key) in chunk.iter_mut().zip([0x18, 0x3f, 0xe2]) {
            *byte ^= key;
        }
    }
    output
}

/// Decodes the size word stored in a serialized RIO reference.
#[must_use]
pub fn decode_size(encoded: u32, bias: u32) -> u32 {
    let value = encoded.wrapping_sub(bias);
    let high = value >> 13;
    value.wrapping_sub(high & 0xfff).wrapping_shl(19) | high
}

#[cfg(test)]
#[path = "../../tests/cipher/rugp.rs"]
mod tests;
