use super::*;
use nvlens_core::Packed;
use nvlens_io::BinaryReader;

pub(super) fn inflate(data: &[u8], size: usize) -> Result<Vec<u8>> {
    nvlens_crypto::compress::csystem::decompress(data, size).map_err(|e| match e {
        nvlens_crypto::compress::CompressError::Truncated { pos } => {
            nvlens_io::BinaryIo::unexpected_eof(format!("C,system LZSS at {pos}")).into()
        }
        e => bad(0, &format!("C,system LZSS: {e}")),
    })
}
fn decimal(bytes: &[u8]) -> Result<u64> {
    let mut value = 0;
    for &byte in bytes {
        let digit = if byte == 255 { 0 } else { byte ^ 127 };
        if digit > 9 {
            return Err(bad(0, "Invalid C,system decimal length"));
        }
        value = value * 10 + u64::from(digit);
    }
    Ok(value)
}
fn envelope(source: &dyn ReadAt) -> Result<(u64, u64)> {
    let bytes = source.read_at(0, 16)?;
    Ok((decimal(&bytes[..8])?, decimal(&bytes[8..])?))
}
pub(super) fn configuration(source: &dyn ReadAt) -> Result<Vec<Entry>> {
    let (unpacked, size) = envelope(source)?;
    let mut entries = vec![Entry {
        name: "configuration.bin".into(),
        offset: 16,
        size,
        kind: ResourceKind::Data,
        packed: Some(Packed {
            unpacked_size: unpacked,
            is_packed: true,
        }),
    }];
    let mut at = 16 + size;
    let mut i = 0;
    while at < source.len() {
        let size = decimal(&source.read_at(at, 8)?)?;
        at += 8;
        entries.push(Entry {
            name: format!("configuration-{i}.bin"),
            offset: at,
            size,
            kind: ResourceKind::Data,
            packed: None,
        });
        at = at
            .checked_add(size)
            .ok_or_else(|| bad(at, "C,system configuration range overflow"))?;
        i += 1;
    }
    Ok(entries)
}
pub(super) fn arc(source: &dyn ReadAt) -> Result<Vec<(Entry, u8)>> {
    let (size, packed) = envelope(source)?;
    let bytes = source.read_at(
        16,
        usize::try_from(packed).map_err(|_| bad(8, "C,system index exceeds address space"))?,
    )?;
    let bytes = inflate(&bytes, size as usize)?;
    let mut r = BinaryReader::new(&bytes);
    let mut entries = Vec::new();
    while r.remaining() != 0 {
        let at = r.position();
        let size = r.read_u32_le()? as usize;
        let mut row = BinaryReader::new(r.read_bytes(size)?);
        let id = row.read_u32_le()?;
        let unpacked = u64::from(row.read_u32_le()?);
        let stored = u64::from(row.read_u32_le()?);
        let offset = u64::from(row.read_u32_le()?);
        let ty = row.read_u8()?;
        let variant = row.read_u8()?;
        row.read_u32_le()?;
        let part = row.read_u8()?;
        if row.remaining() != 0 {
            return Err(bad(at as u64, "Unsupported C,system index record fields"));
        }
        let kind = match ty {
            b'a' | b'f' | b'l' | b'm' | b'e' | b'r' | b's' | b'B' | b'C' | b'x' | b'q' | b't'
            | b'v' | b'c' | b'i' => ResourceKind::Script,
            b'b' | b'n' | b'o' => ResourceKind::Image,
            b'j' | b'k' | b'u' => ResourceKind::Audio,
            b'y' => ResourceKind::Video,
            _ => ResourceKind::Data,
        };
        let entry = Entry {
            name: format!("{id:08}.{}{}", char::from(ty), char::from(variant)),
            kind,
            offset,
            // Music stores three loop parameters before the indexed audio
            // bytes. Its length excludes this prefix (sub_4BA370); the next
            // record may also have an unindexed RIFF header, not audio data.
            size: stored + if ty == b'u' { 12 } else { 0 },
            packed: (unpacked != stored).then_some(Packed {
                unpacked_size: unpacked,
                is_packed: true,
            }),
        };
        entries.push((entry, part));
    }
    Ok(entries)
}
pub(super) struct Table {
    pub start: u64,
    pub size: u64,
    pub entries: Vec<Entry>,
}
pub(super) fn resources(data: &[u8]) -> Result<Vec<Table>> {
    let mut r = BinaryReader::new(data);
    let count = r.read_u32_le()?;
    let mut tables = Vec::new();
    for volume in 0..count {
        let start = r.position() as u64;
        let count = r.read_u32_le()?;
        let rows = r.read_bytes(
            usize::try_from(u64::from(count) * 16)
                .map_err(|_| bad(start, "C,system resource index exceeds address space"))?,
        )?;
        let mut rows = BinaryReader::new(rows);
        let mut entries = Vec::new();
        for ordinal in 0..count {
            let unpacked = u64::from(rows.read_u32_le()?);
            let size = u64::from(rows.read_u32_le()?);
            let offset = rows.read_u64_le()?;
            // sub_41BB00 returns -1 for an uncompressed zero-size slot. These
            // are vacant IDs; later records retain their original ordinals.
            if size == 0 && unpacked == 0 {
                continue;
            }
            let id = (u64::from(volume) + 1) * 10_000_000 + u64::from(ordinal);
            entries.push(Entry {
                name: format!("{id:08}.cimg"),
                kind: ResourceKind::Image,
                offset,
                size,
                packed: (unpacked != 0).then_some(Packed {
                    unpacked_size: unpacked,
                    is_packed: true,
                }),
            });
        }
        let groups = r.read_u32_le()?;
        for _ in 0..groups {
            r.read_bytes(12)?;
            let count = u64::from(r.read_u32_le()?);
            let size = count.saturating_sub(1) * 4 + count * 12;
            r.read_bytes(
                usize::try_from(size)
                    .map_err(|_| bad(start, "C,system animation index exceeds address space"))?,
            )?;
        }
        let flag = r.read_u32_le()?;
        if flag == 1 {
            r.read_u32_le()?;
            let count = u64::from(r.read_u32_le()?);
            r.read_bytes(
                usize::try_from(count * 8)
                    .map_err(|_| bad(start, "C,system mapping index exceeds address space"))?,
            )?;
        }
        tables.push(Table {
            start,
            size: r.position() as u64 - start,
            entries,
        });
    }
    if r.remaining() != 0 {
        return Err(bad(
            r.position() as u64,
            "Trailing C,system resource index data",
        ));
    }
    Ok(tables)
}
#[cfg(test)]
#[path = "../../tests/csystem/index.rs"]
mod tests;
