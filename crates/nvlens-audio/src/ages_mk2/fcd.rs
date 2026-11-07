//! FCD encrypted-audio container (`fz` sound middleware).
//!
//! Encryption is optional, keyed off a chunk of `type == 2`:
//!   seed  = 12 bytes at `0x10 * (encChunkIndex + 1)`,
//!   key16 = MD5(seed || salt[0x4000]),
//!   payload decrypted in place with the custom Blowfish (ECB).
//!
//! Reproduces `fz::sound::SoundObjectBase::decrypt`. Shipped `.fcd` files carry
//! no type-2 chunk, so this is a faithful-but-normally-inactive path.

use nvlens_core::{Error, Result};
use nvlens_crypto::cipher::blowfish::Blowfish;
use nvlens_crypto::hash::md5;
use nvlens_io::BinaryReader;

const MAGIC: &[u8; 4] = b"FCD\0";
const HEADER_SIZE: usize = 0x0C;
const CHUNK_STRIDE: usize = 0x10;
const ENC_CHUNK_TYPE: u32 = 2;

/// Heuristic detector: the `"FCD\0"` magic.
fn looks_like(head: &[u8]) -> bool {
    head.len() >= 4 && &head[..4] == MAGIC
}

/// Returns the encryption chunk index after validating the chunk table.
fn encryption_chunk(data: &[u8]) -> Result<Option<usize>> {
    if !looks_like(data) {
        return Ok(None);
    }
    let mut reader = BinaryReader::new(data);
    reader.read_bytes(6)?;
    let count = usize::from(BinaryReader::u16_be(reader.read_bytes(2)?));
    let end = HEADER_SIZE + CHUNK_STRIDE * count;
    if data.len() < end {
        return Err(nvlens_io::BinaryIo::unexpected_eof("truncated FCD chunk table").into());
    }
    Ok((0..count).find(|&k| {
        BinaryReader::u32_be(&data[HEADER_SIZE + CHUNK_STRIDE * k..][..4]) == ENC_CHUNK_TYPE
    }))
}

/// Indicates whether the container requires the custom Blowfish key tables.
pub fn is_encrypted(data: &[u8]) -> Result<bool> {
    Ok(encryption_chunk(data)?.is_some())
}

/// Per-file audio key = MD5(seed[12] || salt[0x4000]).
fn derive_key(seed: &[u8; 12], salt: &[u8]) -> [u8; 16] {
    md5::digest_parts(&[seed, salt])
}

/// If `data` is an FCD container carrying an encryption (type-2) chunk, decrypt
/// its payload and return the plaintext audio stream; otherwise `None`.
pub fn decrypt_payload_if_encrypted(
    data: &[u8],
    datas: &[u8],
    salt: &[u8],
) -> Result<Option<Vec<u8>>> {
    let Some(enc_at) = encryption_chunk(data)? else {
        return Ok(None);
    };
    let count = usize::from(BinaryReader::u16_be(&data[6..8]));
    let seed_off = CHUNK_STRIDE * (enc_at + 1);
    let seed: &[u8; 12] = data[seed_off..seed_off + 12]
        .try_into()
        .map_err(|_| Error::Corrupt {
            offset: seed_off as u64,
            reason: "invalid FCD seed".into(),
        })?;
    let mut buf = data[HEADER_SIZE + CHUNK_STRIDE * count..].to_vec();
    Blowfish::new(datas, &derive_key(seed, salt))
        .map_err(|e| Error::Corrupt {
            offset: seed_off as u64,
            reason: e.to_string(),
        })?
        .decrypt(&mut buf);
    Ok(Some(buf))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_matches_magic() {
        assert!(looks_like(b"FCD\0\x01\x02"));
        assert!(!looks_like(b"OGGS"));
        assert!(!looks_like(b"FC"));
    }

    #[test]
    fn distinguishes_unencrypted_data_from_truncated_chunk_tables() {
        let mut plain = [0u8; HEADER_SIZE];
        plain[..4].copy_from_slice(MAGIC);
        assert!(!is_encrypted(&plain).unwrap());
        assert!(
            decrypt_payload_if_encrypted(&plain, &[], &[])
                .unwrap()
                .is_none()
        );
        plain[7] = 1;
        assert!(is_encrypted(&plain).is_err());
    }
}
