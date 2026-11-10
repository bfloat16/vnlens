use super::*;

#[test]
fn standard_vectors() {
    // Standard CRC-32 (seed 0) of well-known inputs.
    assert_eq!(ieee(0, b""), 0x0000_0000);
    assert_eq!(ieee(0, b"123456789"), 0xCBF4_3926);
}

#[test]
fn eight_byte_tables_match_bitwise_polynomial_and_incremental_seeds() {
    for offset in 0..16 {
        for len in [0, 1, 7, 8, 9, 15, 16, 17, 255, 4097] {
            let bytes: Vec<_> = (0..offset + len).map(|i| (i * 37 + 91) as u8).collect();
            let bytes = &bytes[offset..];
            for seed in [0, 1, 0x73fb_cbbe, u32::MAX] {
                let mut crc = !seed;
                for &byte in bytes {
                    crc ^= u32::from(byte);
                    for _ in 0..8 {
                        crc = (crc >> 1) ^ (0u32.wrapping_sub(crc & 1) & 0xedb8_8320);
                    }
                }
                assert_eq!(ieee(seed, bytes), !crc);
                let mut streaming = seed;
                for part in bytes.chunks(17) {
                    streaming = ieee(streaming, part);
                }
                assert_eq!(streaming, !crc);
            }
        }
    }
}
