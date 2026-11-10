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
    pub fn apply(&mut self, mut data: &mut [u8]) {
        if self.key_len == Some(0) {
            return;
        }
        while !data.is_empty() {
            if self.key_len == Some(self.position) {
                self.current = self.initial.clone();
                self.position = 0;
            }
            let count = self
                .key_len
                .map_or(data.len(), |length| data.len().min(length - self.position));
            let (mut block, rest) = data.split_at_mut(count);
            let used = self.position % 4;
            if used != 0 {
                let take = block.len().min(4 - used);
                super::xor::apply_stream(&mut block[..take], &self.word[used..used + take]);
                block = &mut block[take..];
            }
            let (words, tail) = block.as_chunks_mut::<4>();
            for word in words {
                BinaryWriter::u32_le(BinaryReader::u32_le(word) ^ self.current.next_u32(), word);
            }
            if !tail.is_empty() {
                BinaryWriter::u32_le(self.current.next_u32(), &mut self.word);
                super::xor::apply_stream(tail, &self.word);
            }
            self.position = self.position.wrapping_add(count);
            data = rest;
        }
    }
}

#[cfg(test)]
#[path = "../../tests/cipher/mdf.rs"]
mod tests;
