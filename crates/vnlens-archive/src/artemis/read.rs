//! PF8 directory layout from CPackFile::open (sub_1401884A0),
//! CFileInfo::deserialize (sub_140099FA0) and CSerializer (sub_1401953B0).
//! The 3-byte "pf8" marker precedes an LE u32 directory length. The directory
//! starts with an LE u32 count, then length-prefixed UTF-8 resource names,
//! serialized source names, and LE u32 absolute offsets/sizes. Serializer
//! field maps follow the records and are included in the SHA-1 payload key.
use std::collections::BTreeSet;
use vnlens_core::{Entry, Error, ResourceKind, Result, Secret};
use vnlens_io::{BinaryIo, BinaryReader, ReadAt};

pub(super) fn index(source: &dyn ReadAt) -> Result<(Vec<Entry>, Secret)> {
    let header = source.read_at(0, 7)?;
    let mut r = BinaryReader::new(&header);
    if r.read_bytes(2)? != b"pf" {
        return Err(Error::InvalidFormat);
    }
    let version = r.read_u8()?;
    if version != b'8' {
        return Err(Error::Unsupported(format!(
            "Artemis PFS version byte 0x{version:02X}"
        )));
    }
    let size = usize::try_from(r.read_u32_le()?)
        .map_err(|_| bad(3, "PFS directory exceeds address space"))?;
    let bytes = source.read_at(7, size)?;
    let key = vnlens_crypto::hash::sha1::Sha1::from(&*bytes)
        .digest()
        .bytes();
    let mut r = BinaryReader::new(&bytes);
    let count = r.read_u32_le()?;
    if u64::from(count) > r.remaining() as u64 / 16 {
        return Err(BinaryIo::unexpected_eof("PFS entry count exceeds its directory").into());
    }
    let mut entries = Vec::new();
    let mut names = BTreeSet::new();
    for _ in 0..count {
        let start = 7 + r.position() as u64;
        let name_size = usize::try_from(r.read_u32_le()?)
            .map_err(|_| bad(start, "PFS name exceeds address space"))?;
        let name = std::str::from_utf8(r.read_bytes(name_size)?)
            .map_err(|_| bad(start, "PFS name is not UTF-8"))?
            .to_owned();
        // The native loader replaces this serialized source name with the
        // containing PFS's path. It is a string, not a flags/reserved word.
        let source_size = usize::try_from(r.read_u32_le()?)
            .map_err(|_| bad(start, "PFS source name exceeds address space"))?;
        r.read_bytes(source_size)?;
        let offset = u64::from(r.read_u32_le()?);
        let size = u64::from(r.read_u32_le()?);
        let entry = Entry {
            name,
            offset,
            size,
            packed: None,
            kind: ResourceKind::Unknown,
        };
        if !entry.check_placement(source.len()) {
            return Err(BinaryIo::unexpected_eof("PFS entry exceeds its source").into());
        }
        // CPackFile's map keeps the first definition within each volume.
        if names.insert(entry.name.replace('/', "\\")) {
            entries.push(entry);
        }
    }
    field_maps(&bytes, r.position())?;
    Ok((entries, Secret::new(key)))
}

// CSerializer appends object-position/field-offset maps, then an absolute
// directory-relative pointer to that table. Unknown field IDs remain opaque.
fn field_maps(bytes: &[u8], records_end: usize) -> Result<()> {
    let footer = bytes
        .len()
        .checked_sub(4)
        .ok_or_else(|| BinaryIo::unexpected_eof("PFS serializer footer is absent"))?;
    let start = usize::try_from(BinaryReader::u32_le(&bytes[footer..]))
        .map_err(|_| bad(7 + footer as u64, "PFS field map exceeds address space"))?;
    if start < records_end || start > footer {
        return Err(bad(
            7 + footer as u64,
            "PFS field map lies outside its directory metadata",
        ));
    }
    let mut r = BinaryReader::new(&bytes[start..footer]);
    let count = u64::from(r.read_u32_le()?);
    if count > r.remaining() as u64 / 8 {
        return Err(BinaryIo::unexpected_eof("PFS object maps exceed their directory").into());
    }
    for _ in 0..count {
        r.read_u32_le()?;
        let size = u64::from(r.read_u32_le()?) * 8;
        r.read_bytes(
            usize::try_from(size)
                .map_err(|_| bad(7 + start as u64, "PFS field map exceeds address space"))?,
        )?;
    }
    Ok(())
}

fn bad(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "../../tests/artemis/read.rs"]
mod tests;
