use super::*;

#[test]
fn forward_matches_cover_periods_alignment_and_exact_capacity() {
    for distance in 1..=96 {
        for offset in 0..16 {
            for count in [0, 1, 2, 15, 16, 17, 31, 32, 33, 257, 4097] {
                let history: Vec<u8> = (0..distance + offset)
                    .map(|i| (i * 47 + 19) as u8)
                    .collect();
                let mut expected = history.clone();
                scalar(&mut expected, distance, count);
                let mut actual = history.into_boxed_slice().into_vec();
                append(&mut actual, distance, count);
                assert_eq!(
                    actual, expected,
                    "distance={distance}, offset={offset}, count={count}"
                );
            }
        }
    }
}

#[test]
fn circular_matches_preserve_wrap_overlap_and_following_dictionary() {
    let history = std::array::from_fn(|i| (i * 47 + 19) as u8);
    for position in [0usize, 1, 15, 16, 17, 2048, 4079, 4080, 4081, 4095] {
        for distance in [0, 1, 2, 3, 15, 16, 17, 31, 32, 4095] {
            for count in [0, 1, 15, 16, 17, 31, 32, 273, 4095, 4101] {
                let mut actual = history;
                let mut expected = history;
                let (mut actual_pos, mut expected_pos) = (position, position);
                let source = position.wrapping_sub(distance) & 4095;
                let (mut actual_out, mut expected_out) = (vec![19; 7], vec![19; 7]);
                ring_scalar(
                    &mut expected,
                    &mut expected_pos,
                    source,
                    count,
                    &mut expected_out,
                );
                ring(&mut actual, &mut actual_pos, source, count, &mut actual_out);
                assert_eq!(actual_out, expected_out);
                assert_eq!(actual, expected);
                assert_eq!(actual_pos, expected_pos);
            }
        }
    }
}
