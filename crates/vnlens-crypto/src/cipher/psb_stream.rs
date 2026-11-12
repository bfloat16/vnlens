//! PSB stream cipher used for encrypted PSB headers and bodies.

use vnlens_io::BinaryWriter;

const KEY1: u32 = 123_456_789;
const KEY2: u32 = 362_436_069;
const KEY3: u32 = 521_288_629;

/// Stateful PSB XorShift128-style stream cipher.
#[derive(Clone)]
pub struct PsbStream {
    key1: u32,
    key2: u32,
    key3: u32,
    key4: u32,
    current: u32,
}

impl std::fmt::Debug for PsbStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PsbStream").finish_non_exhaustive()
    }
}

impl PsbStream {
    /// Creates a stream seeded with the per-file PSB key.
    #[must_use]
    pub fn new(key: u32) -> Self {
        Self {
            key1: KEY1,
            key2: KEY2,
            key3: KEY3,
            key4: key,
            current: 0,
        }
    }

    /// XORs `data` in place. Encryption and decryption are identical.
    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.current == 0 {
                self.next_word();
            }
            let mut word = [0u8; 4];
            BinaryWriter::u32_le(self.current, &mut word);
            *byte ^= word[0];
            self.current >>= 8;
        }
    }

    /// Advances by decoded bytes without reading or retaining the input.
    /// A zero high byte ends a native stream word early, just as in `apply`.
    pub fn skip(&mut self, mut count: u64) {
        while count != 0 {
            if self.current == 0 {
                self.next_word();
            }
            let available = (32 - self.current.leading_zeros()).div_ceil(8);
            let take = count.min(u64::from(available));
            self.current = self.current.checked_shr(take as u32 * 8).unwrap_or(0);
            count -= take;
        }
    }

    fn next_word(&mut self) {
        let a = self.key1 ^ self.key1.wrapping_shl(11);
        let b = self.key4;
        let c = a ^ b ^ ((a ^ (b >> 11)) >> 8);
        self.key1 = self.key2;
        self.key2 = self.key3;
        self.key3 = b;
        self.key4 = c;
        self.current = c;
    }
}

#[cfg(test)]
#[path = "../../tests/cipher/psb_stream.rs"]
mod tests;
