//! ExHIBIT UxRandomMT: ten GYU byte swaps and UxMemoryCrypto's RLD word XOR.
//! RLD encrypts at most 0x3ff0 whole words; its remaining bytes are untouched.

use super::mt19937::Mt19937;
use nvlens_io::{BinaryReader, BinaryWriter};

pub fn unscramble(data: &mut [u8], seed: u32) {
    if data.is_empty() || seed == u32::MAX {
        return;
    }
    let mut mt = Mt19937::legacy(seed);
    for _ in 0..10 {
        let a = mt.next_u32() as usize % data.len();
        let b = mt.next_u32() as usize % data.len();
        data.swap(a, b);
    }
}

pub fn apply_rld(data: &mut [u8], seed: u32) {
    if seed == 0 {
        return;
    }
    let mut mt = Mt19937::legacy(seed);
    let words: [u32; 256] = std::array::from_fn(|_| mt.next_u32() ^ seed);
    for (i, word) in data
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .take(0x3ff0)
        .enumerate()
    {
        BinaryWriter::u32_le(BinaryReader::u32_le(word) ^ words[i % words.len()], word);
    }
}

#[cfg(test)]
#[path = "../../tests/cipher/exhibit.rs"]
mod tests;
