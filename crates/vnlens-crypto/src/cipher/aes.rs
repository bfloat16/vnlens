//! AES-128 ECB/XTS/CTR and AES-256 ECB/CBC primitives. RustCrypto supplies the
//! portable ciphers; x86-64 CTR additionally uses a guarded AES-NI kernel.
use ::aes::{
    Aes128, Aes256,
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
};
use vnlens_io::BinaryWriter;

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
mod simd;

/// Decodes one AES-128 ECB block without padding.
pub fn decrypt_block128(key: &[u8; 16], block: &mut [u8; 16]) {
    Aes128::new(key.into()).decrypt_block(block.into());
}

/// Nintendo AES-XTS data unit: a big-endian sector number and a
/// little-endian GF(2^128) tweak. Units contain complete AES blocks.
pub fn decrypt_xts_sector(key: &[u8; 32], sector: u64, data: &mut [u8; 512]) {
    let cipher = Aes128::new((&key[..16]).into());
    let tweak_cipher = Aes128::new((&key[16..]).into());
    let mut tweak = [0; 16];
    BinaryWriter::u64_be(sector, &mut tweak[8..]);
    tweak_cipher.encrypt_block((&mut tweak).into());
    for block in data.as_chunks_mut::<16>().0 {
        for (byte, mask) in block.iter_mut().zip(tweak) {
            *byte ^= mask;
        }
        cipher.decrypt_block(block.into());
        for (byte, mask) in block.iter_mut().zip(tweak) {
            *byte ^= mask;
        }
        let carry = tweak[15] >> 7;
        for i in (1..16).rev() {
            tweak[i] = (tweak[i] << 1) | (tweak[i - 1] >> 7);
        }
        tweak[0] = (tweak[0] << 1) ^ (carry * 0x87);
    }
}

/// Stateless AES-128 CTR reads, including unaligned stream positions. The
/// counter consists of two big-endian u64 values: upper IV and block position.
pub fn apply_ctr128(key: &[u8; 16], upper: u64, offset: u64, data: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    if simd::apply(key, upper, offset, data) {
        return;
    }
    apply_ctr128_scalar(key, upper, offset, data);
}

fn apply_ctr128_scalar(key: &[u8; 16], upper: u64, offset: u64, data: &mut [u8]) {
    let cipher = Aes128::new(key.into());
    let mut position = offset / 16;
    let mut skip = (offset % 16) as usize;
    let mut remaining = data;
    while !remaining.is_empty() {
        let mut stream = [0; 16];
        BinaryWriter::u64_be(upper, &mut stream[..8]);
        BinaryWriter::u64_be(position, &mut stream[8..]);
        cipher.encrypt_block((&mut stream).into());
        let size = remaining.len().min(16 - skip);
        for (byte, mask) in remaining[..size].iter_mut().zip(&stream[skip..]) {
            *byte ^= mask;
        }
        remaining = &mut remaining[size..];
        position = position.wrapping_add(1);
        skip = 0;
    }
}

/// Decodes one block. The fixed arrays express AES-256's key and block sizes.
pub fn decrypt_block(key: &[u8; 32], block: &mut [u8; 16]) {
    Aes256::new(key.into()).decrypt_block(block.into());
}

/// Decodes complete CBC blocks in place and advances the chaining value, so
/// callers can process chunks and check cancellation between them.
pub fn decrypt_cbc(key: &[u8; 32], iv: &mut [u8; 16], blocks: &mut [[u8; 16]]) {
    let cipher = Aes256::new(key.into());
    for block in blocks {
        let next = *block;
        cipher.decrypt_block(block.into());
        for (byte, previous) in block.iter_mut().zip(iv.iter()) {
            *byte ^= previous;
        }
        *iv = next;
    }
}

#[cfg(test)]
#[path = "../../tests/cipher/aes.rs"]
mod tests;
