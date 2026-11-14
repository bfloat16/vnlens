use super::*;

#[test]
fn ctr_parallel_and_scalar_match_at_unaligned_and_batch_boundaries() {
    for offset in [0, 1, 15, 16, 127, 128, 65529, u64::MAX - 15, u64::MAX] {
        let key = std::array::from_fn(|i| (i as u8).wrapping_mul(17) ^ offset as u8);
        for size in (0..=160).chain([255, 256, 257, 4097]) {
            for start in [0, 1, 7, 15] {
                let mut actual: Vec<_> =
                    (0..size + 32).map(|i| (i as u8).wrapping_mul(29)).collect();
                let mut expected = actual.clone();
                apply_ctr128_scalar(
                    &key,
                    0x0123456789abcdef,
                    offset,
                    &mut expected[start..start + size],
                );
                apply_ctr128(
                    &key,
                    0x0123456789abcdef,
                    offset,
                    &mut actual[start..start + size],
                );
                // Also compare the surrounding bytes to catch stray stores.
                assert_eq!(
                    actual, expected,
                    "offset {offset}, size {size}, alignment {start}"
                );
            }
        }
    }
}

#[test]
fn aes128_ctr_unaligned_random_reads_match_independent_vector() {
    // AES-ECB reference keystream, key 000102...0f, upper IV 0102030405060708,
    // big-endian block counters; bytes 13..61, independently generated.
    let key = std::array::from_fn(|i| i as u8);
    let expected = [
        0x31, 0xe2, 0x78, 0xcf, 0x91, 0xad, 0x9e, 0xdd, 0xf9, 0xce, 0x64, 0x5b, 0x51, 0x5e, 0x23,
        0x82, 0xd1, 0xc8, 0xcc, 0x60, 0x02, 0x68, 0xe2, 0x76, 0xa5, 0x1d, 0x07, 0x29, 0x04, 0xae,
        0x4a, 0x06, 0x47, 0x12, 0xb4, 0x64, 0x33, 0x69, 0xed, 0xf5, 0x34, 0x18, 0x98, 0xac, 0x70,
        0x07, 0x2b, 0xa1,
    ];
    let mut whole = [0; 48];
    apply_ctr128(&key, 0x0102030405060708, 13, &mut whole);
    assert_eq!(whole, expected);
    let mut split = [0; 48];
    apply_ctr128(&key, 0x0102030405060708, 13, &mut split[..7]);
    apply_ctr128(&key, 0x0102030405060708, 20, &mut split[7..]);
    assert_eq!(split, expected);
}

#[test]
fn nintendo_xts_big_endian_sector_matches_independent_vector() {
    // AES-128-XTS reference: key 000102...1f, sector 17 (big-endian tweak),
    // 512 zero ciphertext bytes. Compare the complete plaintext SHA-256.
    let key = std::array::from_fn(|i| i as u8);
    let mut bytes = [0; 512];
    decrypt_xts_sector(&key, 17, &mut bytes);
    assert_eq!(
        crate::hash::sha256::Sha256::digest(&bytes),
        [
            0x57, 0x62, 0xa1, 0xb1, 0xd5, 0x3f, 0x23, 0x28, 0x7b, 0xd0, 0x25, 0xb4, 0x69, 0x9c,
            0x8b, 0xae, 0xea, 0x23, 0xda, 0x65, 0xcb, 0x67, 0xf5, 0x2c, 0x5b, 0x82, 0xcb, 0xbe,
            0x4e, 0x1a, 0xb4, 0x83,
        ]
    );
}

#[test]
fn nist_aes128_ecb_block() {
    let key = std::array::from_fn(|i| i as u8);
    let mut block = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];
    decrypt_block128(&key, &mut block);
    assert_eq!(
        block,
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff
        ]
    );
}
#[test]
fn nist_sp800_38a_cbc_aes256() {
    let key = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
        0xdf, 0xf4,
    ];
    let mut iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let mut blocks = [
        [
            0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b,
            0xfb, 0xd6,
        ],
        [
            0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70,
            0x2c, 0x7d,
        ],
    ];
    let mut first = blocks[0];
    decrypt_block(&key, &mut first);
    decrypt_cbc(&key, &mut iv, &mut blocks[..1]);
    decrypt_cbc(&key, &mut iv, &mut blocks[1..]);
    assert_eq!(
        blocks[0],
        [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a
        ]
    );
    assert_eq!(
        blocks[1],
        [
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
            0x8e, 0x51
        ]
    );
    for (i, b) in first.iter().enumerate() {
        assert_eq!(*b ^ i as u8, blocks[0][i]);
    }
}
