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
mod tests {
    use super::*;

    #[test]
    fn independent_vectors() {
        for (input, expected) in [
            (&b""[..], 0),
            (b"a", 0x9268_5f5e),
            (b"abc", 0x1357_7c9b),
            (b"abcd", 0x2687_3021),
            (b"hello", 0xe561_29cb),
        ] {
            assert_eq!(hash(input, 0), expected);
        }
        assert_eq!(hash(&(0..32).collect::<Vec<u8>>(), 0), 0xf1bc_6c23);
    }
}
