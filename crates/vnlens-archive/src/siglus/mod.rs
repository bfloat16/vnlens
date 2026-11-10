//! Siglus resource containers, routed by the identified engine. Scene indices
//! are unencrypted; per-scene XOR and LZ transforms happen only on access.
mod gameexe;
mod movie;
mod scene;
mod voice;

use vnlens_core::{ArchiveOptions, Error, Result};

fn decode(data: &[u8], options: &ArchiveOptions, table: &str, encrypted: bool) -> Result<Vec<u8>> {
    let mut data = data.to_vec();
    for key in [Some(table), encrypted.then_some("siglus_game")]
        .into_iter()
        .flatten()
    {
        let bytes = options.keys.get(key).ok_or_else(|| {
            Error::UnknownScheme(Some("Missing Siglus resource parameters".into()))
        })?;
        vnlens_crypto::cipher::xor::apply(&mut data, bytes.bytes())
            .map_err(|e| Error::UnknownScheme(Some(e.to_string())))?;
    }
    vnlens_crypto::compress::siglus::decode(&data, 2, 1).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Io(e)
        } else {
            Error::Corrupt {
                offset: 0,
                reason: format!("Siglus LZ: {e}"),
            }
        }
    })
}

#[cfg(test)]
#[path = "../../tests/siglus/mod.rs"]
mod tests;
