//! AGES-MK2 (`smash::fw`) "scramble" cipher: a 64 KiB repeating XOR keystream.
//!
//! `plain[k] = cipher[k] ^ keystream[(start_pos + k) & 0xFFFF]`.
//!
//! The keystream is derived from a caller-supplied 64 KiB base table XORed,
//! block by block, with `MD5(key || BE32(crc32(SEED, blockIndex)))`:
//!
//! ```text
//! ks[i*16 .. i*16+16] = base[i*16 .. i*16+16] ^ MD5(key || BE32(crc32(SEED, BE32(i))))
//! ```
//!
//! Reproduces `smash::fw::util::PackFile::initScramble`.

use crate::checksum::crc32;
use crate::hash::md5;
use nvlens_io::BinaryWriter;

use super::CipherError;

/// Length of the base table and the derived keystream.
const KEYSTREAM_LEN: usize = 0x1_0000;

/// Per-block CRC salt seed used by `initScramble`.
const SEED: u32 = 0x73FB_CBBE;

/// A built 64 KiB keystream for one scramble key.
pub struct Keystream(Box<[u8; KEYSTREAM_LEN]>);

impl std::fmt::Debug for Keystream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keystream").finish_non_exhaustive()
    }
}

impl Keystream {
    /// Reproduces `PackFile::initScramble(key)` over a 64 KiB `base` table.
    pub fn new(base: &[u8], key: &[u8]) -> Result<Self, CipherError> {
        let base: &[u8; KEYSTREAM_LEN] =
            base.try_into().map_err(|_| CipherError::BadScrambleBase {
                expected: KEYSTREAM_LEN,
                got: base.len(),
            })?;
        let mut ks = Box::new(*base);
        for i in 0..(KEYSTREAM_LEN / 16) as u32 {
            let mut counter = [0u8; 4];
            BinaryWriter::u32_be(i, &mut counter);
            let mut checksum = [0u8; 4];
            BinaryWriter::u32_be(crc32::ieee(SEED, &counter), &mut checksum);
            let digest = md5::digest_parts(&[key, &checksum]);
            let base = i as usize * 16;
            for (dst, d) in ks[base..base + 16].iter_mut().zip(digest) {
                *dst ^= d;
            }
        }
        Ok(Keystream(ks))
    }

    /// XOR-decrypts `buf` in place, treating `buf[0]` as logical position `start_pos`.
    pub fn descramble(&self, buf: &mut [u8], start_pos: usize) {
        for (k, b) in buf.iter_mut().enumerate() {
            *b ^= self.0[start_pos.wrapping_add(k) & (KEYSTREAM_LEN - 1)];
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn matches_independent_crc_md5_vector_and_wraps_offsets() {
        let stream = Keystream::new(&[0; KEYSTREAM_LEN], b"test").unwrap();
        let mut first = [0; 16];
        stream.descramble(&mut first, 0);
        assert_eq!(
            first,
            [
                0x6f, 0xaf, 0xad, 0xf0, 0x17, 0xb4, 0xf3, 0x8e, 0x08, 0x95, 0xae, 0xfb, 0x4a, 0x4b,
                0xa8, 0x09
            ]
        );
        let mut wrap = [0; 17];
        stream.descramble(&mut wrap, usize::MAX);
        assert_eq!(&wrap[1..], &first);
        assert!(!format!("{stream:?}").contains("111"));
    }
}
