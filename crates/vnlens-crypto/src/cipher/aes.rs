//! AES-256 ECB block and unpadded CBC decoding using RustCrypto.
use ::aes::{
    Aes256,
    cipher::{BlockDecrypt, KeyInit},
};

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
