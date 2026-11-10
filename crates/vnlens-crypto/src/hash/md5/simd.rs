//! Four independent MD5 messages per SSE2 vector; RFC 1321 rounds are serial
//! within each lane. All byte framing uses BinaryReader/BinaryWriter.
use super::{K, S};
use std::arch::x86_64::*;
use vnlens_io::{BinaryReader, BinaryWriter};

pub(super) fn finish(initial: [u32; 4], blocks: &[[u8; 128]; 4], second: bool) -> [[u8; 16]; 4] {
    let mut out = [[0; 16]; 4];
    // SAFETY: SSE2 is guaranteed by x86-64. Vector arithmetic operates on
    // values; the only pointer stores write exactly four local u32 lanes
    // with unaligned stores. Input bytes are accessed through checked slices.
    unsafe {
        let mut state = initial.map(|word| _mm_set1_epi32(word as i32));
        for offset in [0, 64].into_iter().take(if second { 2 } else { 1 }) {
            let m: [__m128i; 16] = std::array::from_fn(|i| {
                let words: [i32; 4] = std::array::from_fn(|lane| {
                    BinaryReader::u32_le(&blocks[lane][offset + i * 4..offset + i * 4 + 4]) as i32
                });
                _mm_setr_epi32(words[0], words[1], words[2], words[3])
            });
            let [mut a, mut b, mut c, mut d] = state;
            for i in 0..64 {
                let (f, g) = match i {
                    0..=15 => (_mm_or_si128(_mm_and_si128(b, c), _mm_andnot_si128(b, d)), i),
                    16..=31 => (
                        _mm_or_si128(_mm_and_si128(d, b), _mm_andnot_si128(d, c)),
                        (5 * i + 1) % 16,
                    ),
                    32..=47 => (_mm_xor_si128(_mm_xor_si128(b, c), d), (3 * i + 5) % 16),
                    _ => (
                        _mm_xor_si128(c, _mm_or_si128(b, _mm_xor_si128(d, _mm_set1_epi32(-1)))),
                        (7 * i) % 16,
                    ),
                };
                let value = _mm_add_epi32(
                    _mm_add_epi32(f, a),
                    _mm_add_epi32(_mm_set1_epi32(K[i] as i32), m[g]),
                );
                let rotated = _mm_or_si128(
                    _mm_sll_epi32(value, _mm_cvtsi32_si128(S[i] as i32)),
                    _mm_srl_epi32(value, _mm_cvtsi32_si128((32 - S[i]) as i32)),
                );
                a = d;
                d = c;
                c = b;
                b = _mm_add_epi32(b, rotated);
            }
            for (slot, value) in state.iter_mut().zip([a, b, c, d]) {
                *slot = _mm_add_epi32(*slot, value);
            }
        }
        for (i, value) in state.into_iter().enumerate() {
            let mut words = [0u32; 4];
            _mm_storeu_si128(words.as_mut_ptr().cast(), value);
            for (bytes, word) in out.iter_mut().zip(words) {
                BinaryWriter::u32_le(word, &mut bytes[i * 4..i * 4 + 4]);
            }
        }
    }
    out
}
