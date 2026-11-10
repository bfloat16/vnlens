//! SSE2 rotates the low byte through 16-bit multiplication by powers of two.
//! Eight words complete the rotation period; the scalar tail restarts at four.
use std::arch::x86_64::*;

pub(super) fn decrypt(data: &mut [u8]) {
    let (blocks, tail) = data.as_chunks_mut::<32>();
    // SAFETY: x86_64 guarantees SSE2. Each block contains both 16-byte loads
    // and stores; unaligned intrinsics impose no alignment requirement. The
    // mutable slice owns these disjoint blocks, so stores cannot alias readers.
    unsafe {
        let mask = _mm_set1_epi32(255);
        let key = _mm_set1_epi32(0xf7d5859du32 as i32);
        let multipliers = [_mm_set_epi32(128, 64, 32, 16), _mm_set_epi32(8, 4, 2, 1)];
        for block in blocks {
            for (half, multiplier) in block.as_chunks_mut::<16>().0.iter_mut().zip(multipliers) {
                let value = _mm_loadu_si128(half.as_ptr().cast());
                let product = _mm_mullo_epi16(_mm_and_si128(value, mask), multiplier);
                let rotated =
                    _mm_and_si128(_mm_or_si128(product, _mm_srli_epi16::<8>(product)), mask);
                let result =
                    _mm_xor_si128(_mm_or_si128(_mm_andnot_si128(mask, value), rotated), key);
                _mm_storeu_si128(half.as_mut_ptr().cast(), result);
            }
        }
    }
    super::scalar(tail);
}
