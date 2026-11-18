//! Index-only readers. No nested header, DDS payload or sibling name list is
//! read while mounting. Records without native names use extensionless indices.
use super::*;
use vnlens_core::{Error, ResourceKind};
use vnlens_io::{BinaryIo, BinaryReader, Endian};

fn bounds(source: &dyn ReadAt, offset: u64, size: u64) -> Result<()> {
    if offset > source.len() || size > source.len() - offset {
        return Err(BinaryIo::unexpected_eof("Tamsoft range exceeds source").into());
    }
    Ok(())
}
fn bad(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}
fn entry(name: String, offset: u64, size: u64) -> Entry {
    Entry {
        name,
        offset,
        size,
        kind: ResourceKind::Unknown,
        packed: None,
    }
}
fn word(source: &dyn ReadAt, offset: u64, endian: Endian) -> Result<u32> {
    Ok(endian.read_u32(&source.read_at(offset, 4)?))
}

pub(super) fn cat(source: &dyn ReadAt) -> Result<Vec<Entry>> {
    let header = source.read_at(0, 12)?;
    if header[0] & !3 != 0 || header[1..4] != [0; 3] {
        return Err(Error::InvalidFormat);
    }
    let endian = if header[0] & 1 != 0 {
        Endian::Little
    } else {
        Endian::Big
    };
    let count = u64::from(endian.read_u32(&header[4..]));
    bounds(source, 12, count * 12)?;
    let mut entries = Vec::new();
    for group in 0..count {
        let at = u64::from(word(source, 12 + group * 4, endian)?);
        let size = u64::from(word(source, 12 + (count + group) * 4, endian)?);
        let id = word(source, 12 + (count * 2 + group) * 4, endian)?;
        bounds(source, at, size)?;
        if at < 12 + count * 12 || size < 20 {
            return Err(bad(at, "Invalid CAT group range"));
        }
        let header = source.read_at(at, 20)?;
        // The byte flags are not swapped by sub_140592100.
        let flags = BinaryReader::u32_le(&header);
        let records = u64::from(endian.read_u32(&header[4..]));
        let index_size = 20 + records * if flags & 1 != 0 { 12 } else { 8 };
        if index_size > size {
            return Err(bad(at, "CAT record arrays exceed group"));
        }
        for i in 0..records {
            let rel = u64::from(word(source, at + 20 + i * 4, endian)?);
            let length = u64::from(word(source, at + 20 + (records + i) * 4, endian)?);
            if rel > size || length > size - rel {
                return Err(bad(at + 20 + i * 4, "CAT record exceeds group"));
            }
            // A zero offset denotes a null record in sub_140592510.
            if rel == 0 {
                continue;
            }
            if rel < index_size {
                return Err(bad(at + rel, "CAT record overlaps index"));
            }
            let name_offset = if flags & 1 != 0 {
                u64::from(word(source, at + 20 + (records * 2 + i) * 4, endian)?)
            } else {
                0
            };
            let name = if name_offset == 0 {
                i.to_string()
            } else {
                if name_offset < index_size || name_offset >= size {
                    return Err(bad(at + name_offset, "Invalid CAT name offset"));
                }
                let mut bytes = Vec::new();
                let mut pos = name_offset;
                loop {
                    if pos == size {
                        return Err(bad(at + pos, "Unterminated CAT name"));
                    }
                    let byte = source.read_at(at + pos, 1)?[0];
                    pos += 1;
                    if byte == 0 {
                        break;
                    }
                    bytes.push(byte);
                }
                let (text, _, invalid) = encoding_rs::SHIFT_JIS.decode(&bytes);
                if invalid {
                    return Err(bad(at + name_offset, "Invalid CAT CP932 name"));
                }
                text.into_owned()
            };
            entries.push(entry(
                if count == 1 {
                    name
                } else {
                    format!("{id}/{name}")
                },
                at + rel,
                length,
            ));
        }
    }
    Ok(entries)
}

pub(super) fn textures(source: &dyn ReadAt) -> Result<Vec<Entry>> {
    let header = source.read_at(0, 12)?;
    let base = u64::from(BinaryReader::u32_le(&header));
    let count = u64::from(BinaryReader::u32_le(&header[4..]));
    let total = u64::from(BinaryReader::u32_le(&header[8..]));
    if base != 12 + count * 4 || total < base {
        return Err(bad(0, "Invalid Tamsoft texture array"));
    }
    bounds(source, 0, total)?;
    let mut entries = Vec::new();
    for i in 0..count {
        let start = base + u64::from(word(source, 12 + i * 4, Endian::Little)?);
        let end = if i + 1 == count {
            total
        } else {
            base + u64::from(word(source, 16 + i * 4, Endian::Little)?)
        };
        if start > end || end > total {
            return Err(bad(12 + i * 4, "Invalid Tamsoft texture range"));
        }
        entries.push(entry(i.to_string(), start, end - start));
    }
    Ok(entries)
}

pub(super) fn semb(source: &dyn ReadAt) -> Result<Vec<Entry>> {
    let header = source.read_at(0, 24)?;
    if &header[..8] != b"EMOJIPCK" {
        return Err(Error::InvalidFormat);
    }
    if BinaryReader::u32_le(&header[8..]) != 1 || BinaryReader::u32_le(&header[12..]) != 1 {
        return Err(Error::Unsupported("Tamsoft EMOJIPCK version".into()));
    }
    let count = u64::from(BinaryReader::u32_le(&header[16..]));
    let textures = u64::from(BinaryReader::u32_le(&header[20..]));
    if textures != 24 + count * 28 {
        return Err(bad(20, "Tamsoft glyph table length mismatch"));
    }
    bounds(source, 0, textures)?;
    Ok(vec![
        entry("glyphs".into(), 24, count * 28),
        entry("textures".into(), textures, source.len() - textures),
    ])
}
