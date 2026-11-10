//! MurmurHash2, the original 32-bit little-endian variant by Austin Appleby.

use vnlens_io::BinaryReader;

/// Hashes bytes using the original wrapping 32-bit algorithm.
#[must_use]
pub fn hash(data: &[u8], seed: u32) -> u32 {
    let mut state = Murmur2::new(data.len() as u64, seed);
    state.update(data);
    state.finish()
}
const M: u32 = 0x5BD1_E995;
/// Streaming MurmurHash2; total byte length is part of the initial state.
#[derive(Clone, Debug)]
pub struct Murmur2 {
    hash: u32,
    tail: [u8; 4],
    used: usize,
}
impl Murmur2 {
    #[must_use]
    pub fn new(length: u64, seed: u32) -> Self {
        Self {
            hash: seed ^ length as u32,
            tail: [0; 4],
            used: 0,
        }
    }
    fn word(&mut self, word: &[u8]) {
        let mut value = BinaryReader::u32_le(word).wrapping_mul(M);
        value ^= value >> 24;
        self.hash = self.hash.wrapping_mul(M) ^ value.wrapping_mul(M);
    }
    pub fn update(&mut self, mut data: &[u8]) {
        if self.used != 0 {
            let size = (4 - self.used).min(data.len());
            self.tail[self.used..self.used + size].copy_from_slice(&data[..size]);
            self.used += size;
            data = &data[size..];
            if self.used == 4 {
                let word = self.tail;
                self.word(&word);
                self.used = 0;
            } else {
                return;
            }
        }
        let (words, tail) = data.as_chunks::<4>();
        for word in words {
            self.word(word);
        }
        self.tail[..tail.len()].copy_from_slice(tail);
        self.used = tail.len();
    }
    #[must_use]
    pub fn finish(mut self) -> u32 {
        if self.used != 0 {
            let mut word = [0; 4];
            word[..self.used].copy_from_slice(&self.tail[..self.used]);
            self.hash = (self.hash ^ BinaryReader::u32_le(&word)).wrapping_mul(M);
        }
        self.hash ^= self.hash >> 13;
        self.hash = self.hash.wrapping_mul(M);
        self.hash ^ (self.hash >> 15)
    }
}

#[cfg(test)]
#[path = "../../tests/hash/murmur2.rs"]
mod tests;
