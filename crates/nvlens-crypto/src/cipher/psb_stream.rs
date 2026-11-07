//! PSB stream cipher used for encrypted PSB headers and bodies.

use nvlens_io::BinaryWriter;

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
mod tests {
    use super::*;

    #[test]
    fn applies_known_keystream() {
        let mut out = [0u8; 8];
        PsbStream::new(0x1234_5678).apply(&mut out);
        assert_eq!(out, [0x4E, 0x02, 0xDE, 0xCB, 0xAD, 0x53, 0x2C, 0x0C]);
    }

    #[test]
    fn roundtrips_by_reapplying() {
        let data = b"encrypted psb header";
        let mut buf = data.to_vec();
        PsbStream::new(0xCAFEBABE).apply(&mut buf);
        PsbStream::new(0xCAFEBABE).apply(&mut buf);
        assert_eq!(buf, data);
    }
}
