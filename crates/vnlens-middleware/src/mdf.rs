//! M2 MDF/MZS/PSZ compression shells. MDF and MZS contain magic, a u32
//! decoded length, and zlib/Zstandard bytes, optionally encrypted after byte 8.
//! PSZ contains magic, u32 compressed/decoded lengths and a reserved u32 before
//! its complete zlib stream (FreeMote.Plugins.Shells.PszShell).
//! Native references: psbfile.dll 0x10004170 passes all bytes after the MDF
//! header to zlib; MFileReadTask::decode at 0x1404D8770 selects MZS/Zstandard.
use std::{borrow::Cow, io::Read};
use vnlens_core::{Error, Result};
use vnlens_crypto::{
    cipher,
    compress::{zlib, zstd},
};
use vnlens_io::{BinaryReader, ReadAt};

/// Optional filename-derived MDF/MZS decryption parameters.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellKind {
    Mdf,
    Mzs,
    Psz,
}

/// Validated shell framing. Offsets and sizes describe the encoded source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellHeader {
    pub kind: ShellKind,
    pub decoded_len: u64,
    pub payload_offset: u64,
    pub payload_len: u64,
    pub reserved: Option<u32>,
}
impl ShellHeader {
    /// Reads only the shell header, leaving compressed payloads unrequested.
    pub fn read(data: &dyn ReadAt) -> Result<Self> {
        let magic = data.read_at(0, 4)?;
        let kind = match magic.as_ref() {
            b"mdf\0" => ShellKind::Mdf,
            b"mzs\0" => ShellKind::Mzs,
            b"PSZ\0" => ShellKind::Psz,
            _ => return Err(Error::InvalidFormat),
        };
        let head = data.read_at(4, if kind == ShellKind::Psz { 12 } else { 4 })?;
        let (decoded_len, payload_offset, payload_len, reserved) = if kind == ShellKind::Psz {
            let payload_len = u64::from(BinaryReader::u32_le(&head));
            if payload_len > data.len() - 16 {
                return Err(vnlens_io::BinaryIo::unexpected_eof("truncated PSZ payload").into());
            }
            (
                u64::from(BinaryReader::u32_le(&head[4..])),
                16,
                payload_len,
                Some(BinaryReader::u32_le(&head[8..])),
            )
        } else {
            (
                u64::from(BinaryReader::u32_le(&head)),
                8,
                data.len() - 8,
                None,
            )
        };
        Ok(Self {
            kind,
            decoded_len,
            payload_offset,
            payload_len,
            reserved,
        })
    }
}

/// Returns whether a prefix identifies an MDF, MZS or PSZ shell.
#[must_use]
pub fn is_mdf(data: &[u8]) -> bool {
    matches!(data.get(..4), Some(b"mdf\0" | b"mzs\0" | b"PSZ\0"))
}

/// Decodes a complete shell. Declared output lengths and compression checksums
/// are checked; short framing reads preserve `UnexpectedEof`. PSZ does not use
/// the filename-derived cipher. Use `psb::open_source` for lazy mapped access.
pub fn decode(data: &[u8], key: Option<MdfKey<'_>>) -> Result<Vec<u8>> {
    let header = ShellHeader::read(&data)?;
    let start = usize::try_from(header.payload_offset)
        .map_err(|_| corrupt(0, "shell offset does not fit usize"))?;
    let end = start
        .checked_add(
            usize::try_from(header.payload_len)
                .map_err(|_| corrupt(0, "shell size does not fit usize"))?,
        )
        .ok_or_else(|| corrupt(start as u64, "shell range overflow"))?;
    let mut payload = Cow::Borrowed(&data[start..end]);
    if header.kind != ShellKind::Psz
        && let Some(key) = key
    {
        validate_key(key)?;
        cipher::mdf::MdfStream::new(key.key, key.key_len).apply(payload.to_mut());
    }
    let mut decoder: Box<dyn Read + '_> = if header.kind == ShellKind::Mzs {
        Box::new(
            zstd::decoder(payload.as_ref())
                .map_err(|e| corrupt(header.payload_offset, format!("MZS frame failed: {e}")))?,
        )
    } else {
        Box::new(zlib::decoder(payload.as_ref()))
    };
    let mut out = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let count = decoder.read(&mut buffer).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::Io(e)
            } else {
                corrupt(
                    header.payload_offset,
                    format!("shell decompression failed: {e}"),
                )
            }
        })?;
        if count == 0 {
            break;
        }
        if count as u64 > header.decoded_len - out.len() as u64 {
            return Err(corrupt(4, "shell decoded length exceeds its header"));
        }
        out.extend_from_slice(&buffer[..count]);
    }
    if out.len() as u64 != header.decoded_len {
        return Err(corrupt(4, "shell decompressed length mismatch"));
    }
    Ok(out)
}

pub(crate) fn validate_key(key: MdfKey<'_>) -> Result<()> {
    if key.key_len == Some(0) {
        return Err(Error::Unsupported("MDF key length must be positive".into()));
    }
    Ok(())
}
fn corrupt(offset: u64, reason: impl Into<String>) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}
#[cfg(test)]
#[path = "../tests/mdf.rs"]
pub(crate) mod tests;
