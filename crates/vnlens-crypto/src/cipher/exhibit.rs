//! ExHIBIT UxRandomMT: ten GYU byte swaps and UxMemoryCrypto's RLD word XOR.
//! RLD encrypts at most 0x3ff0 whole words; its remaining bytes are untouched.

use super::mt19937::Mt19937;
use vnlens_io::BinaryWriter;

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
    let mut key = [0; 1024];
    for word in key.as_chunks_mut::<4>().0 {
        BinaryWriter::u32_le(mt.next_u32() ^ seed, word);
    }
    let length = (data.len() / 4).min(0x3ff0) * 4;
    for block in data[..length].chunks_mut(key.len()) {
        super::xor::apply_stream(block, &key);
    }
}

#[cfg(test)]
#[path = "../../tests/cipher/exhibit.rs"]
mod tests;
