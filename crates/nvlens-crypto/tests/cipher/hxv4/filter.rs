#![allow(clippy::unwrap_used)]

use super::*;

const PARAMS: [u8; 22] = [
    2, 0, 6, 5, 1, 4, 3, 7, 1, 5, 3, 2, 0, 4, 1, 0, 2, 1, 0xe2, 0x02, 0x83, 0x02,
];

#[test]
fn flat_vm_matches_pre_flattening_drip_regression_values() {
    let table: Vec<u32> = (0..1024u32).map(|x| x.wrapping_mul(0x9e37_79b9)).collect();
    let manager = Filter::from_params_and_table(&PARAMS, &table).unwrap();
    for (input, expected) in [
        (0x0000_0000, 0xa9f8_3ae4_0417_f785),
        (0x0000_0001, 0xffcf_1e06_ffcf_1e07),
        (0x1234_5678, 0x01a0_37fc_83de_a20e),
        (0x5566_7788, 0x8a62_8ff1_4531_47f8),
        (0x1122_3344, 0x0001_9035_0004_376e),
        (0xffff_ffff, 0x000a_9f00_153e_0077),
    ] {
        assert_eq!(manager.drip64(input), expected, "input={input:08x}");
    }
}

#[test]
fn stream_filter_is_symmetric_at_nonzero_offset() {
    let table: Vec<u32> = (0..1024u32)
        .map(|x| x.rotate_left(11) ^ 0xa5a5_5a5a)
        .collect();
    let manager = Filter::from_params_and_table(&PARAMS, &table).unwrap();
    let state = manager.state_for_entry(0x1122_3344_5566_7788, 1);
    let original: Vec<u8> = (0..200u16).map(|x| x as u8).collect();
    let mut data = original.clone();
    state.apply(7, &mut data);
    assert_ne!(data, original);
    state.apply(7, &mut data);
    assert_eq!(data, original);
}
