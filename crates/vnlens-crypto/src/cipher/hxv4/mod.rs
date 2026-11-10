//! Hxv4 bootstrap and authenticated stream primitives. The bootstrap's
//! deriveKeyBlock mixes bytes into eight LE words before BLAKE2s-256;
//! sub_10010550 uses Argon2i v1.3 (8 KiB, 3 passes, 1 lane), SHA3-224 and
//! SHAKE256. BasicCryptoFilter uses SHA3-384 and ChaCha8 with an XOR counter.
//! No native code is executed. See xp3-brute krkr_exe.rs and THIRD_PARTY_NOTICES.md.
mod filter;
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
mod simd;
pub use filter::Filter;

use argon2::{Algorithm, Argon2, Params, Version};
use blake2::Blake2s256;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};
use sha3::{
    Digest, Sha3_224, Sha3_384, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use vnlens_io::{BinaryReader, BinaryWriter};

#[derive(Clone)]
pub struct Keys {
    pub index: [u8; 32],
    pub nonce0: [u8; 24],
    pub nonce1: [u8; 24],
    pub table: [u8; 4096],
}
impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hxv4Keys([redacted])")
    }
}

/// Derives game-wide keys from already resolved executable parameters.
/// Inputs are the exact PARAMS record, UTF-16LE password/unique string and seed.
pub fn derive(
    params: &[u8],
    password: &[u8],
    unique: &[u8],
    seed: &[u8; 8],
) -> Result<Keys, String> {
    if params.len() < 22 {
        return Err("Truncated Hxv4 PARAMS".into());
    }
    let salt = Sha3_224::digest(params);
    let mut material = [0; 64];
    let config = Params::new(8, 3, 1, Some(64)).map_err(|e| e.to_string())?;
    Argon2::new(Algorithm::Argon2i, Version::V0x13, config)
        .hash_password_into(password, &salt[..16], &mut material)
        .map_err(|e| e.to_string())?;
    let mut index = key_block(password, 0);
    let mut alternate = key_block(params, 1);
    let mut holder = key_block(unique, 2);
    let modifier = key_block(seed, BinaryReader::u32_le(seed));
    for i in 0..32 {
        index[i] ^= material[i];
        alternate[i] ^= material[i];
        holder[i] ^= modifier[i];
    }
    let mut nonce0 = [0; 24];
    let mut nonce1 = [0; 24];
    nonce0.copy_from_slice(&holder[..24]);
    nonce1.copy_from_slice(&alternate[..24]);
    let mut shake = Shake256::default();
    Update::update(&mut shake, &material);
    let mut stream = shake.finalize_xof();
    let mut table = [0; 4096];
    stream.read(&mut table);
    if params[17] & 1 != 0 {
        let mut second = [0; 4096];
        stream.read(&mut second);
        for (a, b) in table.iter_mut().zip(second) {
            *a ^= b;
        }
    }
    Ok(Keys {
        index,
        nonce0,
        nonce1,
        table,
    })
}

fn key_block(input: &[u8], seed: u32) -> [u8; 32] {
    let mut words = [0u32; 8];
    let mut state = 0x0100_0193u32.wrapping_mul(seed ^ 0x811c_9dc5);
    for (i, &byte) in input.iter().enumerate() {
        let mut value = u32::from(byte) ^ state;
        value ^= value >> 17;
        value = value.wrapping_mul(0xed5a_d4bb);
        value ^= value >> 11;
        value = value.wrapping_mul(0xac4c_1b51);
        value ^= value >> 15;
        value = value.wrapping_mul(0x3184_8bab);
        state = value ^ (value >> 14);
        words[i % 8] ^= state;
    }
    let mut prehash = [0; 32];
    for (word, bytes) in words.iter().zip(prehash.as_chunks_mut::<4>().0.iter_mut()) {
        BinaryWriter::u32_le(*word, bytes);
    }
    let mut hash = Blake2s256::new();
    Digest::update(&mut hash, input);
    Digest::update(&mut hash, prehash);
    hash.finalize().into()
}

/// Authenticates a tag-prefix XChaCha20-Poly1305 message before returning bytes.
/// Corrupt tags and incorrect keys return an error without releasing plaintext.
pub fn authenticate(blob: &[u8], key: &[u8; 32], nonce: &[u8; 24]) -> Result<Vec<u8>, String> {
    let tag = blob.get(..16).ok_or("Truncated Hxv4 authentication tag")?;
    let mut bytes = blob[16..].to_vec();
    XChaCha20Poly1305::new(key.into())
        .decrypt_in_place_detached(XNonce::from_slice(nonce), b"", &mut bytes, tag.into())
        .map_err(|_| "Hxv4 index authentication failed".to_string())?;
    Ok(bytes)
}

/// Applies the executable's BasicCryptoFilter to a complete resource.
/// `path` is the UTF-16LE filter component from the bres URI, excluding slashes.
#[must_use]
pub fn resource(input: &[u8], path: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut hash = Sha3_384::new();
    Digest::update(&mut hash, path);
    Digest::update(&mut hash, salt);
    let material = hash.finalize();
    let mut initial = [0u32; 16];
    for (word, bytes) in initial
        .iter_mut()
        .zip(b"expand 32-byte k".as_chunks::<4>().0.iter())
    {
        *word = BinaryReader::u32_le(bytes);
    }
    for (word, bytes) in initial[4..12]
        .iter_mut()
        .zip(material[..32].as_chunks::<4>().0.iter())
    {
        *word = BinaryReader::u32_le(bytes);
    }
    initial[12] = BinaryReader::u32_le(&material[40..]);
    initial[13] = BinaryReader::u32_le(&material[44..]);
    initial[14] = BinaryReader::u32_le(&material[32..]);
    initial[15] = BinaryReader::u32_le(&material[36..]);
    let mut output = input.to_vec();
    for (i, chunk) in output.chunks_mut(64).enumerate() {
        let mut state = initial;
        state[12] ^= i as u32;
        #[cfg(target_arch = "x86_64")]
        let x = simd::chacha8(&state);
        #[cfg(not(target_arch = "x86_64"))]
        let x = chacha8_scalar(&state);
        let mut stream = [0; 64];
        for ((a, b), bytes) in x
            .iter()
            .zip(state)
            .zip(stream.as_chunks_mut::<4>().0.iter_mut())
        {
            BinaryWriter::u32_le(a.wrapping_add(b), bytes);
        }
        super::xor::apply_stream(chunk, &stream);
    }
    output
}

#[cfg(test)]
#[path = "../../../tests/cipher/hxv4/mod.rs"]
mod tests;

#[cfg(any(test, not(target_arch = "x86_64")))]
fn chacha8_scalar(state: &[u32; 16]) -> [u32; 16] {
    let mut x = *state;
    for _ in 0..4 {
        for [a, b, c, d] in [
            [0, 4, 8, 12],
            [1, 5, 9, 13],
            [2, 6, 10, 14],
            [3, 7, 11, 15],
            [0, 5, 10, 15],
            [1, 6, 11, 12],
            [2, 7, 8, 13],
            [3, 4, 9, 14],
        ] {
            x[a] = x[a].wrapping_add(x[b]);
            x[d] = (x[d] ^ x[a]).rotate_left(16);
            x[c] = x[c].wrapping_add(x[d]);
            x[b] = (x[b] ^ x[c]).rotate_left(12);
            x[a] = x[a].wrapping_add(x[b]);
            x[d] = (x[d] ^ x[a]).rotate_left(8);
            x[c] = x[c].wrapping_add(x[d]);
            x[b] = (x[b] ^ x[c]).rotate_left(7);
        }
    }
    x
}
