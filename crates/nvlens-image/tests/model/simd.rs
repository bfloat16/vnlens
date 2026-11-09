use super::*;
#[test]
fn matches_scalar_for_offsets_tails_and_all_channel_values() {
    for offset in 0..16 {
        for len in 0..=1027 {
            let mut data: Vec<_> = (0..offset + len + 16).map(|i| i as u8).collect();
            let mut expected = data.clone();
            for pixel in expected[offset..offset + len].as_chunks_mut::<4>().0 {
                pixel.swap(0, 2);
            }
            swap_red_blue(&mut data[offset..offset + len]);
            assert_eq!(data, expected);
        }
    }
}
