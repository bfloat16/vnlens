use super::*;

#[test]
fn standard_vectors() {
    assert_eq!(checksum(b""), 0x0000_0001);
    assert_eq!(checksum(b"Wikipedia"), 0x11E6_0398);

    let data: Vec<u8> = (0..=255).cycle().take(12000).collect();
    let mut state = Adler32::default();
    for chunk in data.chunks(1117) {
        state.update(chunk);
    }
    assert_eq!(state.checksum(), checksum(&data));
}

#[test]
fn vector_sums_match_bytewise_modulo_at_overflow_boundaries() {
    for offset in 0..16 {
        for len in [0, 1, 15, 16, 17, 31, 32, 5551, 5552, 5553, 11104, 100_000] {
            for fill in [false, true] {
                let data: Vec<_> = (0..offset + len)
                    .map(|i| if fill { 255 } else { (i * 37 + 11) as u8 })
                    .collect();
                let data = &data[offset..];
                let (mut a, mut b) = (1u32, 0u32);
                for &byte in data {
                    a = (a + u32::from(byte)) % MOD_ADLER;
                    b = (b + a) % MOD_ADLER;
                }
                let expected = (b << 16) | a;
                assert_eq!(checksum(data), expected);
                for step in [1, 15, 17, 5551, 5552, 5553] {
                    let mut state = Adler32::default();
                    for part in data.chunks(step) {
                        state.update(part);
                    }
                    assert_eq!(state.checksum(), expected);
                }
            }
        }
    }
}
