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

#[test]
fn cxdec_filter_supports_lcg_mt_and_alternate_table_xor() {
    let mut table = vec![0u8; 8192];
    for (i, byte) in table.iter_mut().enumerate() {
        *byte = (i.wrapping_mul(29) ^ 0x5a) as u8;
    }
    let mut lcg_params = PARAMS;
    lcg_params[17] = 0;
    let lcg = Filter::from_cxdec_params_and_table(&lcg_params, &table[..4096]).unwrap();
    let mut mt_params = PARAMS;
    mt_params[17] = 0x81;
    let mt = Filter::from_cxdec_params_and_table(&mt_params, &table).unwrap();
    let mt_plain = Filter::from_cxdec_params_and_table(&mt_params, &table[..4096]).unwrap();

    let original: Vec<u8> = (0..180u16).map(|i| (i * 7) as u8).collect();
    for (filter, hash) in [(&lcg, 0x1234_5678u32), (&mt, 0x89ab_cdefu32)] {
        let mut full = original.clone();
        filter.apply_hash(hash, 0, &mut full);
        assert_ne!(full, original);
        let mut slice = full[13..97].to_vec();
        filter.apply_hash(hash, 13, &mut slice);
        assert_eq!(slice, original[13..97]);
        filter.apply_hash(hash, 0, &mut full);
        assert_eq!(full, original);
    }
    let mut a = original.clone();
    let mut b = original;
    mt.apply_hash(0x1111_2222, 0, &mut a);
    mt_plain.apply_hash(0x1111_2222, 0, &mut b);
    assert_ne!(a, b);

    assert!(Filter::from_cxdec_params_and_table(&lcg_params[..21], &table).is_err());
    assert!(Filter::from_cxdec_params_and_table(&lcg_params, &table[..4095]).is_err());
}
