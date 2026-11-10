//! MT19937 in-place twist. The wrapped part deliberately reads the updated
//! state, matching the original recurrence; batches never cross that boundary.
use super::{LOWER_MASK, M, MATRIX_A, N, UPPER_MASK};
use std::arch::x86_64::*;

pub(super) fn twist(mt: &mut [u32; N]) {
    // SAFETY: SSE2 is baseline on x86-64. The first loop ends before N-M;
    // the second ends before N-1. Every unaligned load/store covers four words
    // within mt. Loads precede stores, and recurrence dependencies are at least
    // N-M words apart, so no lane reads another lane's pending output.
    unsafe {
        let upper = _mm_set1_epi32(UPPER_MASK as i32);
        let lower = _mm_set1_epi32(LOWER_MASK as i32);
        let matrix = _mm_set1_epi32(MATRIX_A as i32);
        let one = _mm_set1_epi32(1);
        for (start, end, wrapped) in [(0, (N - M) / 4 * 4, false), (N - M, N - 1, true)] {
            for i in (start..end).step_by(4) {
                let current = _mm_loadu_si128(mt.as_ptr().add(i).cast());
                let next = _mm_loadu_si128(mt.as_ptr().add(i + 1).cast());
                let source = if wrapped { i - (N - M) } else { i + M };
                let distant = _mm_loadu_si128(mt.as_ptr().add(source).cast());
                let y = _mm_or_si128(_mm_and_si128(current, upper), _mm_and_si128(next, lower));
                let odd = _mm_sub_epi32(_mm_setzero_si128(), _mm_and_si128(y, one));
                let value = _mm_xor_si128(
                    distant,
                    _mm_xor_si128(_mm_srli_epi32::<1>(y), _mm_and_si128(odd, matrix)),
                );
                _mm_storeu_si128(mt.as_mut_ptr().add(i).cast(), value);
            }
            if !wrapped {
                for i in end..N - M {
                    let y = (mt[i] & UPPER_MASK) | (mt[i + 1] & LOWER_MASK);
                    mt[i] = mt[i + M] ^ (y >> 1) ^ (0u32.wrapping_sub(y & 1) & MATRIX_A);
                }
            }
        }
    }
    let y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
    mt[N - 1] = mt[M - 1] ^ (y >> 1) ^ (0u32.wrapping_sub(y & 1) & MATRIX_A);
}
