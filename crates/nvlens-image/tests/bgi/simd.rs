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
