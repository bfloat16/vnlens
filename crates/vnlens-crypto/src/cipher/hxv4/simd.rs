//! ChaCha8 column/diagonal rounds in four SSE2 lanes (RFC 8439 section 2.3).
//! Counter construction and feed-forward addition remain in the caller.
use std::arch::x86_64::*;

pub(super) fn chacha8(state: &[u32; 16]) -> [u32; 16] {
    let mut out = [0; 16];
    // SAFETY: SSE2 is baseline on x86-64. The fixed input and output arrays
    // each contain four complete vectors; unaligned accesses are valid and
    // output owns a separate allocation. No byte-order conversion is performed.
    unsafe {
        let mut a = _mm_loadu_si128(state.as_ptr().cast());
        let mut b = _mm_loadu_si128(state.as_ptr().add(4).cast());
        let mut c = _mm_loadu_si128(state.as_ptr().add(8).cast());
        let mut d = _mm_loadu_si128(state.as_ptr().add(12).cast());
        macro_rules! rotate {
            ($x:expr, $n:literal) => {
                _mm_or_si128(_mm_slli_epi32::<$n>($x), _mm_srli_epi32::<{ 32 - $n }>($x))
            };
        }
        macro_rules! quarter {
            () => {
                a = _mm_add_epi32(a, b);
                d = rotate!(_mm_xor_si128(d, a), 16);
                c = _mm_add_epi32(c, d);
                b = rotate!(_mm_xor_si128(b, c), 12);
                a = _mm_add_epi32(a, b);
                d = rotate!(_mm_xor_si128(d, a), 8);
                c = _mm_add_epi32(c, d);
                b = rotate!(_mm_xor_si128(b, c), 7);
            };
        }
        for _ in 0..4 {
            quarter!();
            b = _mm_shuffle_epi32::<0x39>(b);
            c = _mm_shuffle_epi32::<0x4e>(c);
            d = _mm_shuffle_epi32::<0x93>(d);
            quarter!();
            b = _mm_shuffle_epi32::<0x93>(b);
            c = _mm_shuffle_epi32::<0x4e>(c);
            d = _mm_shuffle_epi32::<0x39>(d);
        }
        for (i, value) in [a, b, c, d].into_iter().enumerate() {
            _mm_storeu_si128(out.as_mut_ptr().add(i * 4).cast(), value);
        }
    }
    out
}
