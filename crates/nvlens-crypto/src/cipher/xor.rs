//! Fixed-width repeating XOR, restarting at the start of each supplied slice.

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
mod simd;

/// Applies a repeating key, restarting at byte zero for each independent block.
pub fn apply(data: &mut [u8], key: &[u8]) -> Result<(), super::CipherError> {
    if key.is_empty() {
        return Err(super::CipherError::EmptyKey);
    }
    #[cfg(target_arch = "x86_64")]
    if key.len().is_multiple_of(16) {
        simd::apply(data, key);
        return Ok(());
    }
    for (byte, key) in data.iter_mut().zip(key.iter().cycle()) {
        *byte ^= key;
    }
    Ok(())
}

pub fn apply_u32_key(data: &mut [u8], key: &[u8; 4]) {
    for (index, byte) in data.iter_mut().enumerate() {
        *byte ^= key[index & 3];
    }
}

/// Decodes little-endian XOR chaining: the first word is the seed, and each
/// following plaintext word is the XOR of adjacent ciphertext words.
pub fn decode_chained_u32(data: &mut [u8]) -> std::io::Result<()> {
    use nvlens_io::{BinaryIo, BinaryReader, BinaryWriter};
    let (words, tail) = data.as_chunks_mut::<4>();
    if !tail.is_empty() || words.is_empty() {
        return Err(BinaryIo::unexpected_eof(
            "XOR chain requires complete words and a seed",
        ));
    }
    let mut previous = BinaryReader::u32_le(&words[0]);
    for word in &mut words[1..] {
        let encoded = BinaryReader::u32_le(word);
        BinaryWriter::u32_le(encoded ^ previous, word);
        previous = encoded;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Short release-mode throughput comparison"]
    fn xor_throughput() -> Result<(), super::super::CipherError> {
        let key: Vec<_> = (0..256).map(|i| (i * 37) as u8).collect();
        let source = vec![0x5a; 4 * 1024 * 1024];
        let mut scalar = source.clone();
        let mut vector = source;
        let start = std::time::Instant::now();
        for _ in 0..31 {
            let data = std::hint::black_box(&mut scalar);
            for (byte, key) in data
                .iter_mut()
                .zip(std::hint::black_box(&key).iter().cycle())
            {
                *byte ^= key;
            }
        }
        let scalar_time = start.elapsed();
        let start = std::time::Instant::now();
        for _ in 0..31 {
            apply(
                std::hint::black_box(&mut vector),
                std::hint::black_box(&key),
            )?;
        }
        println!(
            "XOR 124 MiB: scalar {scalar_time:?}, dispatched {:?}",
            start.elapsed()
        );
        assert_eq!(scalar, vector);
        Ok(())
    }
    #[test]
    fn repeats_and_handles_a_partial_word() {
        let mut bytes = [0, 1, 2, 3, 4, 5, 6];
        apply_u32_key(&mut bytes, &[0x10, 0x20, 0x30, 0x40]);
        assert_eq!(bytes, [0x10, 0x21, 0x32, 0x43, 0x14, 0x25, 0x36]);
        apply_u32_key(&mut bytes, &[0x10, 0x20, 0x30, 0x40]);
        assert_eq!(bytes, [0, 1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn vector_xor_matches_scalar_at_unaligned_boundaries() -> Result<(), super::super::CipherError>
    {
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
}
