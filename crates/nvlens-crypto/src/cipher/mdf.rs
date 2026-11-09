//! MDF MT19937 XOR stream used by some archive PSB resources.

use nvlens_io::{BinaryReader, BinaryWriter};

use crate::hash::md5;

use super::mt19937::Mt19937;

/// Stateful MDF keystream, retaining only the generator state across reads.
#[derive(Clone)]
pub struct MdfStream {
    initial: Mt19937,
    current: Mt19937,
    key_len: Option<usize>,
    position: usize,
    word: [u8; 4],
}

impl std::fmt::Debug for MdfStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdfStream")
            .field("key_len", &self.key_len)
            .finish_non_exhaustive()
    }
}

impl MdfStream {
    #[must_use]
    pub fn new(key: &str, key_len: Option<usize>) -> Self {
        let digest = md5::digest(key.as_bytes());
        let seeds =
            std::array::from_fn::<_, 4, _>(|i| BinaryReader::u32_le(&digest[i * 4..i * 4 + 4]));
        let initial = Mt19937::from_slice(&seeds);
        Self {
            current: initial.clone(),
            initial,
            key_len,
            position: 0,
            word: [0; 4],
        }
    }

    /// Applies the next bytes of the stream, including partial repeated words.
    pub fn apply(&mut self, data: &mut [u8]) {
        if self.key_len == Some(0) {
            return;
        }
        for byte in data {
            if self.key_len == Some(self.position) {
                self.current = self.initial.clone();
                self.position = 0;
            }
            if self.position.is_multiple_of(4) {
                BinaryWriter::u32_le(self.current.next_u32(), &mut self.word);
            }
            *byte ^= self.word[self.position % 4];
            self.position = self.position.wrapping_add(1);
        }
    }
}

#[cfg(test)]
#[path = "../../tests/cipher/mdf.rs"]
mod tests;
