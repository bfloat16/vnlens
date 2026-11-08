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

/// Applies the MDF MT19937 stream, optionally repeating a key buffer.
pub fn apply_mt19937(data: &mut [u8], key: &str, key_len: Option<usize>) {
    MdfStream::new(key, key_len).apply(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_mt19937_array_seed_vector() {
        let mut mt = Mt19937::from_slice(&[0x123, 0x234, 0x345, 0x456]);
        let first = [
            mt.next_u32(),
            mt.next_u32(),
            mt.next_u32(),
            mt.next_u32(),
            mt.next_u32(),
        ];
        assert_eq!(
            first,
            [
                1_067_595_299,
                955_945_823,
                477_289_528,
                4_107_218_783,
                4_228_976_476
            ]
        );
    }

    #[test]
    fn mdf_keystream_matches_known_vector() {
        let mut encoded = [0u8; 16];
        apply_mt19937(&mut encoded, "demo_info.psb.m", Some(131));
        assert_eq!(
            encoded,
            [
                0x62, 0x72, 0xA2, 0x03, 0x3D, 0xF1, 0xBC, 0x5D, 0x2A, 0xA5, 0xD6, 0x49, 0x26, 0x4C,
                0x93, 0xE4
            ]
        );
    }

    #[test]
    fn roundtrips_by_reapplying() {
        let data = b"encrypted mdf body";
        let mut buf = data.to_vec();
        apply_mt19937(&mut buf, "archive/file.psb.m", Some(131));
        apply_mt19937(&mut buf, "archive/file.psb.m", Some(131));
        assert_eq!(buf, data);
    }

    #[test]
    fn streaming_matches_partial_repeated_words() {
        let mut whole = [0u8; 300];
        apply_mt19937(&mut whole, "demo_info.psb.m", Some(131));
        let mut split = [0u8; 300];
        let mut stream = MdfStream::new("demo_info.psb.m", Some(131));
        for chunk in split.chunks_mut(7) {
            stream.apply(chunk);
        }
        assert_eq!(whole, split);
        assert_eq!(&whole[..131], &whole[131..262]);
    }
}
