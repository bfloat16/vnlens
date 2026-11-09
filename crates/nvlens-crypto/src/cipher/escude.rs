//! ESC-ARC index keystream, checked against OpenFastFile (0x441900).
//! Each index word consumes one state transition; payloads are not encrypted.

pub struct IndexCipher(u32);
impl std::fmt::Debug for IndexCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexCipher").finish_non_exhaustive()
    }
}
impl IndexCipher {
    #[must_use]
    pub fn new(seed: u32) -> Self {
        Self(seed)
    }

    pub fn decode_word(&mut self, word: u32) -> u32 {
        self.0 ^= 0x65ac_9365;
        self.0 ^= ((self.0 >> 1) ^ self.0) >> 3 ^ ((self.0 << 1) ^ self.0) << 3;
        word ^ self.0
    }
}

#[cfg(test)]
#[path = "../../tests/cipher/escude.rs"]
mod tests;
