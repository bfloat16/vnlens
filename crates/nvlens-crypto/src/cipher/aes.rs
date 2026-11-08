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
mod tests {
    use super::*;
    #[test]
    fn nist_sp800_38a_cbc_aes256() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let mut iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut blocks = [
            [
                0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b,
                0xfb, 0xd6,
            ],
            [
                0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70,
                0x2c, 0x7d,
            ],
        ];
        let mut first = blocks[0];
        decrypt_block(&key, &mut first);
        decrypt_cbc(&key, &mut iv, &mut blocks[..1]);
        decrypt_cbc(&key, &mut iv, &mut blocks[1..]);
        assert_eq!(
            blocks[0],
            [
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a
            ]
        );
        assert_eq!(
            blocks[1],
            [
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
                0x8e, 0x51
            ]
        );
        for (i, b) in first.iter().enumerate() {
            assert_eq!(*b ^ i as u8, blocks[0][i]);
        }
    }
}
