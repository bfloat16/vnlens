//! RealLive SEEN compiler header (0x1D0 bytes, LE), kidoku/read flags,
//! counted CP932 names, and its interleaved expression/command bytecode.
//! Layout and transforms follow SeenManager::LoadAndDecryptSeen and VM::
//! DispatchHashCommand/ParseMemRef; the original header and unknown fields
//! remain in document sections. No VM instructions are executed.
mod bytecode;
mod header;
use crate::{ScriptFormat, ScriptRegistration, ir::Script};
use header::Header;
use std::borrow::Cow;
use vnlens_core::{ArchiveOptions, Error, Format, ResourceResolver, Result};
use vnlens_io::BinaryReader;

fn corrupt(offset: usize, reason: &str) -> Error {
    Error::Corrupt {
        offset: offset as u64,
        reason: reason.into(),
    }
}

#[derive(Debug, Default)]
struct RealLive;
impl Format for RealLive {
    fn tag(&self) -> &'static str {
        "script/reallive"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x0000_01d0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["txt", "ini"]
    }
    fn description(&self) -> &'static str {
        "RealLive SEEN bytecode and Gameexe configuration"
    }
}
impl ScriptFormat for RealLive {
    fn decode_text(&self, data: &[u8]) -> Result<Option<String>> {
        if data.starts_with(&[0xd0, 1, 0, 0]) {
            return Ok(None);
        }
        let (text, _, invalid) = encoding_rs::SHIFT_JIS.decode(data);
        if invalid {
            return Err(corrupt(0, "Invalid RealLive CP932 configuration"));
        }
        Ok(Some(text.into_owned()))
    }
    fn disassemble(&self, data: &[u8], _: Option<&dyn ResourceResolver>) -> Result<Option<Script>> {
        self.disassemble_with_options(data, None, &ArchiveOptions::default())
    }
    fn disassemble_with_options(
        &self,
        data: &[u8],
        _: Option<&dyn ResourceResolver>,
        options: &ArchiveOptions,
    ) -> Result<Option<Script>> {
        if !data.starts_with(&[0xd0, 1, 0, 0]) {
            return Ok(None);
        }
        let header = Header::parse(data)?;
        let plain = decode(data, options)?;
        bytecode::parse(&plain, &header).map(Some)
    }
}
vnlens_core::inventory::submit! { ScriptRegistration(||Box::new(RealLive)) }

fn key<'a>(options: &'a ArchiveOptions, name: &str, length: usize) -> Result<&'a [u8]> {
    options
        .keys
        .get(name)
        .map(|k| k.bytes())
        .filter(|k| k.len() == length)
        .ok_or_else(|| Error::UnknownScheme(Some(format!("Missing or invalid RealLive {name}"))))
}

fn decode<'a>(data: &'a [u8], options: &ArchiveOptions) -> Result<Cow<'a, [u8]>> {
    if !data.starts_with(&[0xd0, 1, 0, 0]) {
        return Ok(Cow::Borrowed(data));
    }
    let h = Header::parse(data)?;
    if h.version % 100 == 1 {
        return Ok(Cow::Borrowed(data));
    }
    let stored = h.stored as usize;
    let offset = h.code as usize;
    let mut r = BinaryReader::new_at(data, offset)?;
    let mut packed = r.read_bytes(stored)?.to_vec();
    let table = key(options, "reallive_xor", 256)?;
    vnlens_crypto::cipher::xor::apply(&mut packed, table)
        .map_err(|e| Error::UnknownScheme(Some(e.to_string())))?;
    let mut body = vnlens_crypto::compress::siglus::decode(&packed, 2, 1).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Io(e)
        } else {
            corrupt(offset, "Invalid RealLive compressed bytecode")
        }
    })?;
    if body.len() as u64 != h.size {
        return Err(corrupt(offset, "RealLive bytecode size mismatch"));
    }
    for (enabled, name, start) in [
        (h.version / 100000 % 10 != 0, "reallive_key1", 0x100usize),
        (h.version / 1000000 % 10 != 0, "reallive_key2", 0x180usize),
    ] {
        if enabled {
            let bytes = key(options, name, 16)?;
            let end = body.len().min(start + 0x101);
            if start < end {
                vnlens_crypto::cipher::xor::apply(&mut body[start..end], bytes)
                    .map_err(|e| Error::UnknownScheme(Some(e.to_string())))?;
            }
        }
    }
    let mut plain = data[..offset].to_vec();
    plain.extend(body);
    plain.extend(r.read_bytes(r.remaining())?);
    Ok(Cow::Owned(plain))
}

#[cfg(test)]
#[path = "../../tests/reallive/mod.rs"]
mod tests;
