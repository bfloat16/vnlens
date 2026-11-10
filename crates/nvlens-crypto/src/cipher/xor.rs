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
    if data.len() >= 16 {
        simd::apply(data, key);
        return Ok(());
    }
    for (byte, key) in data.iter_mut().zip(key.iter().cycle()) {
        *byte ^= key;
    }
    Ok(())
}

pub fn apply_u32_key(data: &mut [u8], key: &[u8; 4]) {
    #[cfg(target_arch = "x86_64")]
    if data.len() >= 16 {
        simd::apply(data, key);
        return;
    }
    for (index, byte) in data.iter_mut().enumerate() {
        *byte ^= key[index & 3];
    }
}

/// XORs the common prefix of a buffer and a non-repeating keystream.
pub(crate) fn apply_stream(data: &mut [u8], key: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    let processed = simd::stream(data, key);
    #[cfg(not(target_arch = "x86_64"))]
    let processed = 0;
    for (byte, mask) in data[processed..].iter_mut().zip(&key[processed..]) {
        *byte ^= mask;
    }
}

/// Decodes little-endian XOR chaining: the first word is the seed, and each
/// following plaintext word is the XOR of adjacent ciphertext words.
pub fn decode_chained_u32(data: &mut [u8]) -> std::io::Result<()> {
    use nvlens_io::BinaryIo;
    let (words, tail) = data.as_chunks_mut::<4>();
    if !tail.is_empty() || words.is_empty() {
        return Err(BinaryIo::unexpected_eof(
            "XOR chain requires complete words and a seed",
        ));
    }
    #[cfg(target_arch = "x86_64")]
    simd::chained(words);
    #[cfg(not(target_arch = "x86_64"))]
    decode_chained_scalar(words);
    Ok(())
}

#[cfg(any(test, not(target_arch = "x86_64")))]
fn decode_chained_scalar(words: &mut [[u8; 4]]) {
    use nvlens_io::{BinaryReader, BinaryWriter};
    let mut previous = BinaryReader::u32_le(&words[0]);
    for word in &mut words[1..] {
        let encoded = BinaryReader::u32_le(word);
        BinaryWriter::u32_le(encoded ^ previous, word);
        previous = encoded;
    }
}

#[cfg(test)]
#[path = "../../tests/cipher/xor.rs"]
mod tests;
