use super::*;

#[test]
fn twist_matches_scalar_across_multiple_generations() {
    for seed in [0, 1, 5489, 0x8000_0000, u32::MAX] {
        for mut actual in [
            Mt19937::legacy(seed),
            Mt19937::seed_from_u32(seed),
            Mt19937::from_slice(&[seed, !seed]),
        ] {
            let mut expected = actual.clone();
            for _ in 0..12 {
                actual.twist();
                twist_scalar(&mut expected.mt);
                assert_eq!(actual.mt, expected.mt);
            }
        }
    }
}
