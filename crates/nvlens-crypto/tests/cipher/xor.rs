use super::*;

#[test]
fn vector_xor_matches_scalar_at_unaligned_boundaries() -> Result<(), super::super::CipherError> {
    for key_len in [1, 15, 16, 32, 256, 512] {
        let key: Vec<_> = (0..key_len).map(|i| (i * 37) as u8).collect();
        for offset in 0..16 {
            for len in [0, 1, 15, 16, 17, 255, 256, 257, 1027] {
                let mut data: Vec<_> = (0..len + offset + 17).map(|i| (i * 11) as u8).collect();
                let mut expected = data.clone();
                for (i, b) in expected[offset..offset + len].iter_mut().enumerate() {
                    *b ^= key[i % key_len];
                }
                apply(&mut data[offset..offset + len], &key)?;
                assert_eq!(data, expected);
            }
        }
    }
    Ok(())
}
