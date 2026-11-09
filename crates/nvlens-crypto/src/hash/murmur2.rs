//! MurmurHash2, the original 32-bit little-endian variant by Austin Appleby.

use nvlens_io::BinaryReader;

/// Hashes bytes using the original wrapping 32-bit algorithm.
#[must_use]
pub fn hash(data: &[u8], seed: u32) -> u32 {
    const M: u32 = 0x5BD1_E995;
    let mut hash = seed ^ data.len() as u32;
    let (words, tail) = data.as_chunks::<4>();
    for word in words {
        let mut value = BinaryReader::u32_le(word).wrapping_mul(M);
        value ^= value >> 24;
        hash = hash.wrapping_mul(M) ^ value.wrapping_mul(M);
    }
    if !tail.is_empty() {
        let mut word = [0; 4];
        word[..tail.len()].copy_from_slice(tail);
        hash = (hash ^ BinaryReader::u32_le(&word)).wrapping_mul(M);
    }
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(M);
    hash ^ (hash >> 15)
}

#[cfg(test)]
#[path = "../../tests/hash/murmur2.rs"]
mod tests;
