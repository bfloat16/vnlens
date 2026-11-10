//! Database-EPK decryption (`smash::fw::util::Crypt::decode`).
//!
//! A database EPK has no magic: the whole file is custom-Blowfish ciphertext
//! plus a 0x30 trailer, decrypting to a `"DAT"` text table. The Blowfish key is
//! the file's name stem. (The unencrypted `"EPK\0"` resource form is left as-is.)

use vnlens_core::{Error, Result};
use vnlens_crypto::cipher::blowfish::Blowfish;
use vnlens_crypto::hash::md5;
use vnlens_io::BinaryReader;

/// Magic of the unencrypted resource EPK.
const RES_MAGIC: &[u8; 4] = b"EPK\0";
/// MD5 integrity salt appended to the ciphertext (ASCII, 32 bytes).
const SALT: &[u8] = b"8FE9D249BD2689BB4B70F5AE88A9E645";
const TRAILER: usize = 0x30;

/// True for the unencrypted `EPK\0` resource format.
#[must_use]
pub fn is_resource(head: &[u8]) -> bool {
    head.len() >= 4 && &head[..4] == RES_MAGIC
}

/// Database-EPK Blowfish key = filename stem (basename minus last extension).
#[must_use]
pub fn key_from_name(name: &str) -> Vec<u8> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let stem = match base.rfind('.') {
        Some(i) if i > 0 => &base[..i],
        _ => base,
    };
    stem.as_bytes().to_vec()
}

/// Reproduce `Crypt::decode`: validate the MD5 trailer, Blowfish-decrypt, and
/// truncate to the stored plaintext length. Returns the `"DAT"` table bytes.
pub fn decrypt(raw: &[u8], key: &[u8], datas: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < TRAILER {
        return Err(Error::InvalidFormat);
    }
    let ct_len = raw.len() - TRAILER;
    if !ct_len.is_multiple_of(4) {
        return Err(Error::InvalidFormat);
    }
    let (ct, tr) = raw.split_at(ct_len);

    if md5::digest_parts(&[ct, SALT])[..] != tr[0x20..0x30] {
        return Err(Error::InvalidFormat);
    }

    let org_len = BinaryReader::u32_be(&tr[0x10..0x14]) as usize;
    if org_len > ct_len {
        return Err(Error::Corrupt {
            offset: (ct_len + 0x10) as u64,
            reason: "EPK plaintext length exceeds ciphertext".into(),
        });
    }
    let mut buf = ct.to_vec();
    Blowfish::new(datas, key)
        .map_err(|e| Error::Corrupt {
            offset: 0,
            reason: e.to_string(),
        })?
        .decrypt(&mut buf);
    buf.truncate(org_len);
    Ok(buf)
}

#[cfg(test)]
#[path = "../../tests/ages_mk2/epk.rs"]
mod tests;
