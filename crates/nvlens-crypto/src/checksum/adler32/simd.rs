//! Adler's two sums over 16-byte lanes: b += 16*a + dot(bytes, 16..1).
//! The caller reduces modulo 65521 every 5552 bytes (RFC 1950's u32 bound).
use std::arch::x86_64::*;

pub(super) fn update(a: &mut u32, b: &mut u32, bytes: &[u8]) -> usize {
    let (blocks, _) = bytes.as_chunks::<16>();
    // SAFETY: SSE2 is baseline on x86-64. Each block is exactly 16 initialized
    // bytes, unaligned loads are valid, and local stores target four u32 lanes.
    // a/b are exclusive references; no input or output pointers alias.
    unsafe {
        let zero = _mm_setzero_si128();
        let low_weights = _mm_setr_epi16(16, 15, 14, 13, 12, 11, 10, 9);
        let high_weights = _mm_setr_epi16(8, 7, 6, 5, 4, 3, 2, 1);
        let mut sums = zero;
        let mut weighted = zero;
        let mut preceding = zero;
        for block in blocks {
            let bytes = _mm_loadu_si128(block.as_ptr().cast());
            preceding = _mm_add_epi32(preceding, sums);
            sums = _mm_add_epi32(sums, _mm_sad_epu8(bytes, zero));
            weighted = _mm_add_epi32(
                weighted,
                _mm_add_epi32(
                    _mm_madd_epi16(_mm_unpacklo_epi8(bytes, zero), low_weights),
                    _mm_madd_epi16(_mm_unpackhi_epi8(bytes, zero), high_weights),
                ),
            );
        }
        weighted = _mm_add_epi32(weighted, _mm_slli_epi32::<4>(preceding));
        let mut lanes = [0u32; 4];
        _mm_storeu_si128(lanes.as_mut_ptr().cast(), weighted);
        *b += blocks.len() as u32 * 16 * *a + lanes.iter().sum::<u32>();
        _mm_storeu_si128(lanes.as_mut_ptr().cast(), sums);
        *a += lanes.iter().sum::<u32>();
    }
    blocks.len() * 16
}
