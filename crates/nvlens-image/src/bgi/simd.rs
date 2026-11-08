//! x86-64 SSE2 AAN inverse transform. SSE2 is mandatory on x86-64. The safe
//! entry accepts fixed-size arrays; loads/stores are unaligned and remain
//! within those arrays. Operation order matches the scalar implementation.
use std::arch::x86_64::*;

pub(super) fn inverse(data: &[i16; 64], quant: &[f32; 64]) -> [u8; 64] {
    // SAFETY: x86-64 guarantees SSE2; fixed arrays provide every lane accessed
    // by transform, with no alignment requirement and no aliasing of writes.
    unsafe { transform(data, quant) }
}

#[target_feature(enable = "sse2")]
unsafe fn transform(data: &[i16; 64], quant: &[f32; 64]) -> [u8; 64] {
    let mut temporary = [0f32; 64];
    // SAFETY: group is 0 or 4 and row is 0..8. Each 8-byte sample load and
    // 16-byte float load/store lies within a row of the 64-element arrays.
    unsafe {
        for group in [0, 4] {
            let mut input = [_mm_setzero_ps(); 8];
            for (row, value) in input.iter_mut().enumerate() {
                let packed = _mm_loadl_epi64(data.as_ptr().add(row * 8 + group).cast());
                let integers = _mm_srai_epi32::<16>(_mm_unpacklo_epi16(packed, packed));
                *value = _mm_mul_ps(
                    _mm_cvtepi32_ps(integers),
                    _mm_loadu_ps(quant.as_ptr().add(row * 8 + group)),
                );
            }
            for (row, value) in aan(input).into_iter().enumerate() {
                _mm_storeu_ps(temporary.as_mut_ptr().add(row * 8 + group), value);
            }
        }
    }
    let mut output = [0u8; 64];
    for group in [0, 4] {
        let input = std::array::from_fn(|column| {
            _mm_set_ps(
                temporary[(group + 3) * 8 + column],
                temporary[(group + 2) * 8 + column],
                temporary[(group + 1) * 8 + column],
                temporary[group * 8 + column],
            )
        });
        for (column, value) in aan(input).into_iter().enumerate() {
            let ints = _mm_cvttps_epi32(value);
            let shorts = _mm_packs_epi32(ints, ints);
            let pixels = _mm_packus_epi16(
                _mm_add_epi16(_mm_srai_epi16::<3>(shorts), _mm_set1_epi16(128)),
                _mm_setzero_si128(),
            );
            let mut lanes = [0u8; 16];
            // SAFETY: lanes contains 16 writable bytes; storeu has no alignment
            // requirement. Only the first four byte lanes correspond to rows.
            unsafe {
                _mm_storeu_si128(lanes.as_mut_ptr().cast(), pixels);
            }
            for row in 0..4 {
                output[(group + row) * 8 + column] = lanes[row];
            }
        }
    }
    output
}

#[target_feature(enable = "sse2")]
fn aan(v: [__m128; 8]) -> [__m128; 8] {
    let sum = _mm_add_ps(v[0], v[4]);
    let difference = _mm_sub_ps(v[0], v[4]);
    let diagonal = _mm_add_ps(v[2], v[6]);
    let rotated = _mm_sub_ps(
        _mm_mul_ps(
            _mm_sub_ps(v[2], v[6]),
            _mm_set1_ps(std::f32::consts::SQRT_2),
        ),
        diagonal,
    );
    let even = [
        _mm_add_ps(sum, diagonal),
        _mm_add_ps(difference, rotated),
        _mm_sub_ps(difference, rotated),
        _mm_sub_ps(sum, diagonal),
    ];
    let outer = _mm_add_ps(v[1], v[7]);
    let outer_delta = _mm_sub_ps(v[1], v[7]);
    let inner = _mm_add_ps(v[5], v[3]);
    let inner_delta = _mm_sub_ps(v[5], v[3]);
    let odd_sum = _mm_add_ps(outer, inner);
    let rotation = _mm_mul_ps(_mm_add_ps(outer_delta, inner_delta), _mm_set1_ps(1.847759));
    let odd1 = _mm_sub_ps(
        _mm_add_ps(_mm_mul_ps(_mm_set1_ps(-2.613126), inner_delta), rotation),
        odd_sum,
    );
    let odd2 = _mm_sub_ps(
        _mm_mul_ps(
            _mm_sub_ps(outer, inner),
            _mm_set1_ps(std::f32::consts::SQRT_2),
        ),
        odd1,
    );
    let odd3 = _mm_add_ps(
        odd2,
        _mm_sub_ps(_mm_mul_ps(_mm_set1_ps(1.0823922), outer_delta), rotation),
    );
    [
        _mm_add_ps(even[0], odd_sum),
        _mm_add_ps(even[1], odd1),
        _mm_add_ps(even[2], odd2),
        _mm_sub_ps(even[3], odd3),
        _mm_add_ps(even[3], odd3),
        _mm_sub_ps(even[2], odd2),
        _mm_sub_ps(even[1], odd1),
        _mm_sub_ps(even[0], odd_sum),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sse2_matches_scalar_for_dc_sparse_and_extreme_coefficients() {
        let mut state = 0x1234_5678u32;
        for iteration in 0..2048 {
            let data = std::array::from_fn(|index| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                if iteration < 64 && index != iteration {
                    0
                } else {
                    state as i16
                }
            });
            let quant =
                std::array::from_fn(|index| ((index + iteration) % 255 + 1) as f32 * 0.27589938);
            assert_eq!(
                inverse(&data, &quant),
                super::super::dct::inverse_scalar(&data, &quant)
            );
        }
    }
    #[test]
    #[ignore = "Manual release-mode SIMD microbenchmark; no window or device"]
    fn benchmark_idct() {
        let data = std::array::from_fn(|i| i as i16 - 32);
        let quant = [1.; 64];
        for (name, run) in [
            (
                "scalar",
                super::super::dct::inverse_scalar as fn(&[i16; 64], &[f32; 64]) -> [u8; 64],
            ),
            ("sse2", inverse),
        ] {
            let start = std::time::Instant::now();
            for _ in 0..100_000 {
                std::hint::black_box(run(
                    std::hint::black_box(&data),
                    std::hint::black_box(&quant),
                ));
            }
            println!("IDCT {name}: {:?}", start.elapsed());
        }
    }
}
