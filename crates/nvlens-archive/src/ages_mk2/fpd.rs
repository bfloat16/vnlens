//! FPD container — `smash::fw::util::PackFile`.
//!
//! Layout (multi-byte header/TOC fields are **big-endian**):
//! ```text
//!   0x00  "FPD\0"                              (plaintext header, 0x38 bytes)
//!   0x04  u32 version          (=2)
//!   0x08  u64 entryCount
//!   0x10  u64 indexSize        (= start offset of the data region)
//!   0x18  u8[0x20] reserved (0)
//!   0x38  scrambled index region [0x38, indexSize):
//!             entryCount * FpdEntry(0x20)   then   filename table (zlib if version>=2)
//!   indexSize  scrambled file data region
//! ```
//! Each region is descrambled with the keystream starting at logical position 0.
//! The 64 KiB scramble base table is loaded from the `bin/` sidecar via
//! [`nvlens_bin`]; the scramble key is supplied by engine identification.

use std::borrow::Cow;
use std::sync::Arc;

use nvlens_audio::fcd;
use nvlens_bin::keys;
use nvlens_core::{
    ArcView, Archive, ArchiveFormat, Entry, Error, Format, Packed, ResourceKind, Result,
    register_archive,
};
use nvlens_crypto::cipher::scramble::Keystream;
use nvlens_crypto::compress::zlib;
use nvlens_io::{BinaryReader, Endian};
use nvlens_script::epk;

const SIGNATURES: &[u32] = &[0x0044_5046];
const MAGIC: &[u8; 4] = b"FPD\0";
const HEADER_SIZE: u64 = 0x38;
const ENTRY_SIZE: usize = 0x20;

/// The FPD archive format.
#[derive(Debug, Default)]
struct FpdArc;

impl Format for FpdArc {
    fn tag(&self) -> &'static str {
        "fpd"
    }

    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["fpd", "dat"]
    }

    fn description(&self) -> &'static str {
        "AGES-MK2 (smash::fw) PackFile archive"
    }
}

impl ArchiveFormat for FpdArc {
    fn open(
        &self,
        view: &Arc<ArcView>,
        options: &nvlens_core::ArchiveOptions,
    ) -> Result<Box<dyn Archive>> {
        let key = options.keys.get("scramble").ok_or_else(|| {
            Error::UnknownScheme(Some("Missing identified FPD scramble key".into()))
        })?;
        // Header is plaintext and big-endian.
        if view.len() < 4 || view.slice(0, 4)? != MAGIC {
            return Err(Error::InvalidFormat);
        }
        let head = view.slice(0, HEADER_SIZE)?;
        let mut r = BinaryReader::new(head);
        let _ = r.read_bytes(4)?; // magic
        let version = r.read_u32(Endian::Big)?;
        let entry_count = r.read_u64(Endian::Big)?;
        let index_size = r.read_u64(Endian::Big)?;

        // Scrambled index region [HEADER_SIZE, index_size).
        let payload_len = index_size
            .checked_sub(HEADER_SIZE)
            .ok_or_else(|| Error::Corrupt {
                offset: 0x10,
                reason: "indexSize smaller than header".into(),
            })?;
        if entry_count > payload_len / ENTRY_SIZE as u64 {
            return Err(Error::Corrupt {
                offset: 8,
                reason: "FPD entry count exceeds index storage".into(),
            });
        }
        let enc = view.slice(HEADER_SIZE, payload_len)?;

        let base = nvlens_bin::load(keys::ages_mk2::SCRAMBLE_BASE)?;
        let keystream =
            Arc::new(
                Keystream::new(&base, key.bytes()).map_err(|e| Error::Corrupt {
                    offset: 0,
                    reason: e.to_string(),
                })?,
            );
        let mut index = enc.to_vec();
        keystream.descramble(&mut index, 0);
        let entries = parse_index(version, entry_count, index_size, view.len(), &index)
            .ok_or_else(|| Error::Corrupt {
                offset: HEADER_SIZE,
                reason: "Invalid FPD index for identified key".into(),
            })?;
        Ok(Box::new(FpdArchive {
            view: Arc::clone(view),
            keystream,
            entries,
        }))
    }
}

/// Parse the descrambled index into entries; `None` if it does not look valid
/// after the engine has selected the scramble key.
fn parse_index(
    version: u32,
    entry_count: u64,
    index_size: u64,
    file_len: u64,
    index: &[u8],
) -> Option<Vec<Entry>> {
    let count = usize::try_from(entry_count).ok()?;
    let toc_len = count.checked_mul(ENTRY_SIZE)?;
    if toc_len > index.len() {
        return None;
    }

    // Raw TOC: four big-endian u64 per entry.
    let mut raw = Vec::with_capacity(count);
    let mut r = BinaryReader::new(&index[..toc_len]);
    for _ in 0..count {
        let name_offset = r.read_u64(Endian::Big).ok()?;
        let data_offset = r.read_u64(Endian::Big).ok()?;
        let stored_size = r.read_u64(Endian::Big).ok()?;
        let org_size = r.read_u64(Endian::Big).ok()?;
        raw.push((name_offset, data_offset, stored_size, org_size));
    }

    // Filename table (zlib-compressed from version 2). A wrong key yields
    // non-zlib bytes here, so inflation failing rejects it.
    let name_blob = &index[toc_len..];
    let names = if version >= 2 {
        zlib::inflate(name_blob).ok()?
    } else {
        name_blob.to_vec()
    };
    if let Some(&(name_offset, ..)) = raw.first()
        && usize::try_from(name_offset).ok()? >= names.len().max(1)
    {
        return None;
    }

    let mut entries = Vec::with_capacity(count);
    for (name_offset, data_offset, stored_size, org_size) in raw {
        let name = resolve_name(&names, usize::try_from(name_offset).ok()?)?;
        let offset = index_size.checked_add(data_offset)?;
        let entry = Entry {
            kind: ResourceKind::guess_from_name(&name),
            name,
            offset,
            size: stored_size,
            // org_size == 0 means stored verbatim; otherwise zlib-compressed.
            packed: (org_size != 0).then_some(Packed {
                unpacked_size: org_size,
                is_packed: true,
            }),
        };
        if !entry.check_placement(file_len) {
            return None;
        }
        entries.push(entry);
    }
    Some(entries)
}

/// Resolve a NUL-terminated name at `start` within the filename table.
fn resolve_name(names: &[u8], start: usize) -> Option<String> {
    let tail = names.get(start..)?;
    let end = tail.iter().position(|&byte| byte == 0)?;
    String::from_utf8(tail[..end].to_vec()).ok()
}

/// An opened FPD archive.
#[derive(Debug)]
struct FpdArchive {
    view: Arc<ArcView>,
    keystream: Arc<Keystream>,
    entries: Vec<Entry>,
}

impl Archive for FpdArchive {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let buf = self.decode_entry(entry)?;
        Ok(Cow::Owned(post_process(buf, &entry.name)?))
    }

    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
}

impl FpdArchive {
    fn decode_entry(&self, entry: &Entry) -> Result<Vec<u8>> {
        let mut buf = self.view.slice(entry.offset, entry.size)?.to_vec();
        if !buf.is_empty() {
            self.keystream.descramble(&mut buf, 0);
        }
        if let Some(packed) = entry.packed.filter(|p| p.is_packed) {
            let expected = usize::try_from(packed.unpacked_size)
                .map_err(|_| Error::Unsupported("FPD output does not fit address space".into()))?;
            buf = zlib::inflate_with_limit(&buf, expected).map_err(|e| Error::Corrupt {
                offset: entry.offset,
                reason: e.to_string(),
            })?;
            if buf.len() != expected {
                return Err(Error::Corrupt {
                    offset: entry.offset,
                    reason: "FPD decompressed length mismatch".into(),
                });
            }
        }
        Ok(buf)
    }
}

/// Auto-detect and decrypt a descrambled entry's nested container (database EPK
/// or encrypted FCD audio); returns the bytes unchanged when nothing applies.
fn post_process(data: Vec<u8>, name: &str) -> Result<Vec<u8>> {
    if has_ext(name, "epk") && !epk::is_resource(&data) {
        let datas = nvlens_bin::load(keys::ages_mk2::EPK_BLOWFISH_DATAS)?;
        match epk::decrypt(&data, &epk::key_from_name(name), &datas) {
            Ok(plain) => return Ok(plain),
            Err(Error::InvalidFormat) => {}
            Err(error) => return Err(error),
        }
    }
    if fcd::is_encrypted(&data)? {
        let datas = nvlens_bin::load(keys::ages_mk2::SOUND_BLOWFISH_DATAS)?;
        let salt = nvlens_bin::load(keys::ages_mk2::SOUND_MD5_SALT)?;
        if let Some(payload) = fcd::decrypt_payload_if_encrypted(&data, &datas, &salt)? {
            return Ok(payload);
        }
    }
    Ok(data)
}

fn has_ext(name: &str, ext: &str) -> bool {
    name.rsplit('.')
        .next()
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

register_archive!(FpdArc);

#[cfg(test)]
#[path = "../../tests/ages_mk2/fpd.rs"]
mod tests;
