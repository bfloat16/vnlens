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
mod tests {
    use super::*;
    #[test]
    fn native_header_vector_and_continuous_state() {
        let mut cipher = IndexCipher::new(0x3526_4916);
        assert_eq!(cipher.decode_word(0xd368_592b), 281);
        assert_eq!(cipher.decode_word(0x711a_e1d4), 4244);
        assert_eq!(cipher.decode_word(0xf9be_fb3b), 0);
        assert_eq!(cipher.decode_word(0xa7e4_d914), 7636);
    }
}
