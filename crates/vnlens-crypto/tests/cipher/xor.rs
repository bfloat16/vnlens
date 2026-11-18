use super::*;

#[test]
fn random_access_keeps_the_stream_phase() -> Result<(), super::super::CipherError> {
    let mut bytes = [0; 8];
    apply_at(&mut bytes, &[0x10, 0x20, 0x30], 4)?;
    assert_eq!(bytes, [0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30]);
    apply_at(&mut bytes, &[0x10, 0x20, 0x30], 4)?;
    assert_eq!(bytes, [0; 8]);
    assert!(apply_at(&mut [], &[], 0).is_err());
    Ok(())
}

#[test]
fn vector_xor_matches_scalar_at_unaligned_boundaries() -> Result<(), super::super::CipherError> {
    for key_len in [1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33, 63, 256, 512] {
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

#[test]
fn chained_words_keep_ciphertext_carry_and_reject_partial_words() -> std::io::Result<()> {
    for offset in 0..16 {
        for count in 1..80 {
            let mut data: Vec<_> = (0..count * 4 + offset + 5)
                .map(|i| (i * 29 + 113) as u8)
                .collect();
            let mut expected = data.clone();
            decode_chained_scalar(expected[offset..offset + count * 4].as_chunks_mut::<4>().0);
            decode_chained_u32(&mut data[offset..offset + count * 4])?;
            assert_eq!(data, expected);
        }
    }
    for len in [0, 1, 2, 3, 5, 7, 17] {
        assert!(decode_chained_u32(&mut vec![0; len]).is_err());
    }
    Ok(())
}

#[test]
fn fixed_key_and_stream_xor_preserve_tails() {
    for offset in 0..16 {
        for len in 0..80 {
            let mut data: Vec<_> = (0..len + offset + 17).map(|i| (i * 11) as u8).collect();
            let key = [1, 17, 231, 4];
            let mut expected = data.clone();
            for (i, byte) in expected[offset..offset + len].iter_mut().enumerate() {
                *byte ^= key[i % 4];
            }
            apply_u32_key(&mut data[offset..offset + len], &key);
            assert_eq!(data, expected);
            let mask: Vec<_> = (0..len / 2).map(|i| (i * 47) as u8).collect();
            for (byte, key) in expected[offset..offset + len].iter_mut().zip(&mask) {
                *byte ^= key;
            }
            apply_stream(&mut data[offset..offset + len], &mask);
            assert_eq!(data, expected);
        }
    }
}
