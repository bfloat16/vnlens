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
#[path = "../../tests/cipher/xor.rs"]
mod tests;
