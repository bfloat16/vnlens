//! Custom Blowfish used by several engines (e.g. AGES-MK2 `Crypt` / `SoundCrypt`).
//!
//! Blowfish's Feistel structure with two non-standard tweaks:
//! - the P-array and S-boxes come from an engine-specific constant table (NOT
//!   the pi digits), supplied by the caller;
//! - the S-boxes are a single array read through four **overlapping** windows:
//!
//! ```text
//!     F(x) = ( S[b3] + S[b2+4] ) ^ S[b1+8] ^ S[b0+12]
//!     b3 = x>>24, b2 = (x>>16)&0xff, b1 = (x>>8)&0xff, b0 = x&0xff   (adds mod 2^32)
//! ```
//!
//! Blocks are big-endian; mode is ECB (no IV). The constant table holds 1042
//! big-endian u32 (18 P-words + four 256-word S source blocks copied into the
//! live state with the same overlapping bases), i.e. 4168 bytes.

use nvlens_io::{BinaryReader, BinaryWriter};

use super::CipherError;

/// Number of bytes consumed from the constant table (1042 * 4).
const TABLE_LEN: usize = 4168;

/// Live key state: 18 P-words and a 268-entry overlapping-window S-array.
pub struct Blowfish {
    p: [u32; 18],
    s: [u32; 268],
}

impl std::fmt::Debug for Blowfish {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blowfish").finish_non_exhaustive()
    }
}

impl Blowfish {
    /// Builds the schedule from a constant table (>= 4168 bytes) and a raw key.
    pub fn new(datas: &[u8], key: &[u8]) -> Result<Self, CipherError> {
        if key.is_empty() {
            return Err(CipherError::EmptyKey);
        }
        if datas.len() < TABLE_LEN {
            return Err(CipherError::BadBlowfishTable {
                expected: TABLE_LEN,
                got: datas.len(),
            });
        }
        // The table is a flat array of big-endian u32; read word `i`.
        let w = |i: usize| BinaryReader::u32_be(&datas[4 * i..4 * i + 4]);

        let mut p = [0u32; 18];
        for (i, slot) in p.iter_mut().enumerate() {
            *slot = w(i);
        }
        let mut s = [0u32; 268];
        for (j, slot) in s[0..256].iter_mut().enumerate() {
            *slot = w(18 + j); // block 1
        }
        for (j, slot) in s[4..260].iter_mut().enumerate() {
            *slot = w(274 + j); // block 2 (overlaps)
        }
        for (j, slot) in s[8..264].iter_mut().enumerate() {
            *slot = w(530 + j); // block 3
        }
        for (j, slot) in s[12..268].iter_mut().enumerate() {
            *slot = w(786 + j); // block 4
        }
        let mut bf = Blowfish { p, s };

        // XOR the key (big-endian, cycled) into the 18 P-words.
        let mut j = 0usize;
        for slot in &mut bf.p {
            let mut bytes = [0u8; 4];
            for byte in &mut bytes {
                *byte = key[j];
                j = if j + 1 == key.len() { 0 } else { j + 1 };
            }
            *slot ^= BinaryReader::u32_be(&bytes);
        }

        // Zero-block key schedule: regenerate P then the four S blocks.
        let (mut l, mut r) = (0u32, 0u32);
        let mut i = 0;
        while i < 18 {
            let e = bf.enc(l, r);
            l = e.0;
            r = e.1;
            bf.p[i] = l;
            bf.p[i + 1] = r;
            i += 2;
        }
        for base in [0usize, 4, 8, 12] {
            let mut n = 0;
            while n < 256 {
                let e = bf.enc(l, r);
                l = e.0;
                r = e.1;
                bf.s[base + n] = l;
                bf.s[base + n + 1] = r;
                n += 2;
            }
        }
        Ok(bf)
    }

    #[inline]
    fn f(&self, x: u32) -> u32 {
        let b3 = (x >> 24) as usize & 0xff;
        let b2 = (x >> 16) as usize & 0xff;
        let b1 = (x >> 8) as usize & 0xff;
        let b0 = x as usize & 0xff;
        (self.s[b3].wrapping_add(self.s[4 + b2])) ^ self.s[8 + b1] ^ self.s[12 + b0]
    }

    fn enc(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        for i in 0..16 {
            l ^= self.p[i];
            r ^= self.f(l);
            std::mem::swap(&mut l, &mut r);
        }
        std::mem::swap(&mut l, &mut r);
        r ^= self.p[16];
        l ^= self.p[17];
        (l, r)
    }

    fn dec(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        for i in (2..=17).rev() {
            l ^= self.p[i];
            r ^= self.f(l);
            std::mem::swap(&mut l, &mut r);
        }
        std::mem::swap(&mut l, &mut r);
        r ^= self.p[1];
        l ^= self.p[0];
        (l, r)
    }

    /// Decrypts `data` in place (ECB, big-endian blocks). A trailing partial
    /// block (< 8 bytes) is left unchanged, matching the engine's `execcoder`.
    pub fn decrypt(&self, data: &mut [u8]) {
        let n = data.len() & !7;
        let mut o = 0;
        while o < n {
            let l = BinaryReader::u32_be(&data[o..o + 4]);
            let r = BinaryReader::u32_be(&data[o + 4..o + 8]);
            let (l, r) = self.dec(l, r);
            BinaryWriter::u32_be(l, &mut data[o..o + 4]);
            BinaryWriter::u32_be(r, &mut data[o + 4..o + 8]);
            o += 8;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn independent_custom_table_vector_and_empty_key() {
        let mut table = vec![0u8; TABLE_LEN];
        for (i, word) in table.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            BinaryWriter::u32_be(i as u32, word);
        }
        assert!(matches!(
            Blowfish::new(&table, &[]),
            Err(CipherError::EmptyKey)
        ));
        assert!(Blowfish::new(&table[..10], b"test").is_err());
        let cipher = Blowfish::new(&table, b"test").unwrap();
        let mut data = [0x37, 0x01, 0xba, 0x3b, 0xfe, 0x3e, 0x4d, 0xce, 0x55];
        cipher.decrypt(&mut data);
        assert_eq!(&data[..8], b"ABCDEFGH");
        assert_eq!(data[8], 0x55);
        assert_eq!(format!("{cipher:?}"), "Blowfish { .. }");
    }
}
