//! SSE2 RGBA/BGRA channel exchange, preserving alpha and green exactly.
use std::arch::x86_64::*;
pub(super) fn swap_red_blue(bytes: &mut [u8]) {
    // SAFETY: SSE2 is guaranteed on x86-64. All accesses are bounded by the
    // exclusive slice; unaligned operations impose no pointer alignment rule.
    unsafe {
        swap(bytes);
    }
}
#[target_feature(enable = "sse2")]
unsafe fn swap(bytes: &mut [u8]) {
    let whole = bytes.len() / 16 * 16;
    let rb = _mm_set1_epi32(0x00ff00ff);
    // SAFETY: each iteration reads/writes exactly 16 bytes within whole. The
    // input and output are the same exclusive allocation, and loads precede stores.
    unsafe {
        for at in (0..whole).step_by(16) {
            let value = _mm_loadu_si128(bytes.as_ptr().add(at).cast());
            let outside = _mm_andnot_si128(rb, value);
            let swapped = _mm_or_si128(
                _mm_slli_epi32::<16>(_mm_and_si128(value, rb)),
                _mm_and_si128(_mm_srli_epi32::<16>(value), rb),
            );
            _mm_storeu_si128(
                bytes.as_mut_ptr().add(at).cast(),
                _mm_or_si128(outside, swapped),
            );
        }
    }
    let (pixels, _) = bytes[whole..].as_chunks_mut::<4>();
    for pixel in pixels {
        pixel.swap(0, 2);
    }
}

#[cfg(test)]
#[path = "../../tests/model/simd.rs"]
mod tests;
