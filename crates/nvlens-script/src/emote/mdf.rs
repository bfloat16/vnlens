//! MDF shell decoding: magic, little-endian original length, then zlib.
//! The decoder at 0x10004170 passes the complete payload after byte 8 to zlib.

use nvlens_core::{Error, Result};
use nvlens_crypto::cipher;
use nvlens_crypto::compress::zlib;
use nvlens_io::BinaryReader;

const MAGIC: &[u8; 4] = b"mdf\0";
const HEADER_LEN: usize = 8;
const ZLIB_HEADER_LEN: usize = 2;
const CHECKSUM_LEN: usize = 4;

/// Optional MDF decryption parameters.
#[derive(Clone, Copy)]
pub struct MdfKey<'a> {
    pub key: &'a str,
    pub key_len: Option<usize>,
}

impl std::fmt::Debug for MdfKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdfKey")
            .field("key_len", &self.key_len)
            .finish_non_exhaustive()
    }
}

/// Returns true when `data` starts with an MDF shell signature.
#[must_use]
pub fn is_mdf(data: &[u8]) -> bool {
    data.len() >= MAGIC.len() && &data[..MAGIC.len()] == MAGIC
}

/// Decodes an MDF shell to the contained PSB or resource bytes.
///
/// # Errors
///
/// Returns corrupt-data errors for truncated headers, bad checksums, unknown
/// compression headers, or inflate failures.
pub fn decode(data: &[u8], key: Option<MdfKey<'_>>) -> Result<Vec<u8>> {
    if !is_mdf(data) {
        return Err(Error::InvalidFormat);
    }
    if data.len() < HEADER_LEN + ZLIB_HEADER_LEN + CHECKSUM_LEN {
        return Err(corrupt(0, "MDF is too small"));
    }
    let expected_len = usize::try_from(BinaryReader::u32_le(&data[4..8]))
        .map_err(|_| corrupt(4, "MDF original length does not fit usize"))?;

    let mut decoded = std::borrow::Cow::Borrowed(data);
    if let Some(key) = key {
        if key.key_len == Some(0) {
            return Err(Error::Unsupported("MDF key length must be positive".into()));
        }
        cipher::mdf::MdfStream::new(key.key, key.key_len)
            .apply(&mut decoded.to_mut()[HEADER_LEN..]);
    }

    let out = zlib::inflate_with_limit(&decoded[HEADER_LEN..], expected_len)
        .map_err(|e| corrupt(HEADER_LEN as u64, format!("MDF inflate failed: {e}")))?;
    if out.len() != expected_len {
        return Err(corrupt(4, "MDF decompressed length mismatch"));
    }

    Ok(out)
}

fn corrupt(offset: u64, reason: impl Into<String>) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "../../tests/emote/mdf.rs"]
pub(crate) mod tests;
