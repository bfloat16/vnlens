//! YPF 0x1DF..=0x1F4. Index readers 0x4564A4 (0x1DF), 0x45D01C
//! (0x1E6), 0x45CBE0 (0x1EA), 0x45DB10 (0x1ED), 0x45EC64 (0x1EE)
//! and 0x464314 (0x1F4) share this layout. All integers are little-endian.
//! The header's index end includes its 0x20 bytes. Records contain
//! substituted name lengths, XOR names, type/packing, unpacked/stored lengths,
//! a 32/64-bit file offset, and filename/stored-payload checksums. Clients use
//! either MurmurHash2 for names and stored payloads (sub_439780), or IEEE CRC32
//! for names and Adler32 for stored payloads. Index parsing never reads payloads.
//! Both length substitutions occur in 0x1F4 archives; exact record coverage,
//! name checksums and payload ranges select the layout and checksum scheme;
//! the version alone does not distinguish these variants.

use std::{
    borrow::Cow,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
use vnlens_core::{ArcView, Archive, Entry, Error, Packed, ResourceKind, Result, Secret};
use vnlens_crypto::{
    checksum::{adler32, crc32},
    compress::zlib,
    hash::murmur2,
};
use vnlens_io::{BinaryReader, ReadAt};

/// Filename-length involution constructed by clients preceding 0x1F4.
pub(super) const LENGTH_SWAPS_PRE_1F4: &[(u8, u8)] = &[
    (3, 72),
    (6, 53),
    (9, 11),
    (12, 16),
    (13, 19),
    (17, 25),
    (21, 27),
    (28, 30),
    (32, 35),
    (38, 41),
    (44, 47),
    (46, 50),
];
/// Filename-length involution constructed by the 0x1F4 client.
pub(super) const LENGTH_SWAPS_1F4: &[(u8, u8)] = &[
    (3, 10),
    (6, 53),
    (9, 11),
    (12, 16),
    (13, 19),
    (17, 24),
    (21, 27),
    (28, 30),
    (32, 35),
    (38, 41),
    (44, 47),
    (46, 20),
];

/// Decoded index and stored-payload checksums in matching entry order.
#[derive(Debug)]
pub(super) struct Index {
    pub entries: Vec<Entry>,
    pub checksums: Vec<u32>,
    pub checksum_scheme: ChecksumScheme,
    /// Empty archives cannot determine an unknown filename key.
    pub name_key: Option<Secret>,
}

/// Paired filename and stored-payload algorithms selected by the complete index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ChecksumScheme {
    Murmur2,
    Crc32Adler32,
}

impl ChecksumScheme {
    fn filename(self, bytes: &[u8]) -> u32 {
        match self {
            Self::Murmur2 => murmur2::hash(bytes, 0),
            Self::Crc32Adler32 => crc32::ieee(0, bytes),
        }
    }

    fn payload(self, bytes: &[u8]) -> u32 {
        match self {
            Self::Murmur2 => murmur2::hash(bytes, 0),
            Self::Crc32Adler32 => adler32::checksum(bytes),
        }
    }
}

#[derive(Clone, Copy)]
struct Layout {
    swaps: &'static [(u8, u8)],
    width: usize,
    checksum_scheme: ChecksumScheme,
}

fn length(encoded: u8, swaps: &[(u8, u8)]) -> usize {
    let value = !encoded;
    usize::from(
        swaps
            .iter()
            .find_map(|&(a, b)| {
                if value == a {
                    Some(b)
                } else if value == b {
                    Some(a)
                } else {
                    None
                }
            })
            .unwrap_or(value),
    )
}

fn check_cancelled(cancel: Option<&AtomicBool>) -> Result<()> {
    if cancel.is_some_and(|cancel| cancel.load(Ordering::Relaxed)) {
        return Err(Error::Cancelled);
    }
    Ok(())
}

/// Reads only index bytes. Without a supplied key, intersects all 256 possible
/// filename XOR values against stored name hashes. The complete index must
/// select one checksum scheme and layout; conflicting candidates fail.
pub(super) fn read_index(
    source: &dyn ReadAt,
    name_key: Option<u8>,
    cancelled: Option<&AtomicBool>,
) -> Result<Index> {
    check_cancelled(cancelled)?;
    let header = source.read_at(0, 32)?;
    let mut reader = BinaryReader::new(&header);
    if reader.read_bytes(4)? != b"YPF\0" {
        return Err(Error::InvalidFormat);
    }
    let version = reader.read_u32_le()?;
    let tables = match version {
        0x1df..=0x1f3 => &[LENGTH_SWAPS_PRE_1F4][..],
        0x1f4 => &[LENGTH_SWAPS_1F4, LENGTH_SWAPS_PRE_1F4][..],
        _ => return Err(Error::Unsupported(format!("YPF version 0x{version:X}"))),
    };
    let count = reader.read_u32_le()? as usize;
    let index_end = u64::from(reader.read_u32_le()?);
    let index_size = index_end
        .checked_sub(32)
        .ok_or_else(|| corrupt(12, "Index end precedes header"))?;
    let index = source.read_at(
        32,
        usize::try_from(index_size).map_err(|_| corrupt(12, "Index exceeds address space"))?,
    )?;
    if count > index.len() / 23 {
        return Err(corrupt(8, "Entry count exceeds index record capacity"));
    }
    let mut found: Option<Index> = None;
    let mut first_error = None;
    for swaps in tables {
        for width in [4, 8] {
            for checksum_scheme in [ChecksumScheme::Murmur2, ChecksumScheme::Crc32Adler32] {
                match parse_index(
                    &index,
                    source.len(),
                    index_end,
                    count,
                    Layout {
                        swaps,
                        width,
                        checksum_scheme,
                    },
                    name_key,
                    cancelled,
                ) {
                    Ok(parsed) => {
                        if let Some(previous) = &found {
                            let same = (count == 0
                                || previous.checksum_scheme == parsed.checksum_scheme)
                                && previous.name_key == parsed.name_key
                                && previous.checksums == parsed.checksums
                                && previous.entries.iter().zip(&parsed.entries).all(|(a, b)| {
                                    a.name == b.name
                                        && a.kind == b.kind
                                        && a.offset == b.offset
                                        && a.size == b.size
                                        && a.packed.map(|p| (p.unpacked_size, p.is_packed))
                                            == b.packed.map(|p| (p.unpacked_size, p.is_packed))
                                });
                            if !same {
                                return Err(Error::UnknownScheme(Some(
                                    "Ambiguous YPF index layout".into(),
                                )));
                            }
                        } else {
                            found = Some(parsed);
                        }
                    }
                    Err(Error::Cancelled) => return Err(Error::Cancelled),
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
        }
    }
    found.ok_or_else(|| first_error.unwrap_or_else(|| corrupt(32, "No matching YPF index layout")))
}

fn parse_index(
    index: &[u8],
    source_len: u64,
    index_end: u64,
    count: usize,
    layout: Layout,
    name_key: Option<u8>,
    cancelled: Option<&AtomicBool>,
) -> Result<Index> {
    let Layout {
        swaps,
        width,
        checksum_scheme,
    } = layout;
    let name_key = match name_key {
        Some(key) => Some(key),
        None if count == 0 => None,
        None => Some(recover_name_key(index, count, layout, cancelled)?),
    };
    let mut reader = BinaryReader::new(index);
    let mut entries = Vec::with_capacity(count);
    let mut checksums = Vec::with_capacity(count);
    for _ in 0..count {
        check_cancelled(cancelled)?;
        let record_offset = reader.position() as u64 + 32;
        let hash = reader.read_u32_le()?;
        let size = length(reader.read_u8()?, swaps);
        let encoded = reader.read_bytes(size)?;
        let key = name_key
            .ok_or_else(|| Error::UnknownScheme(Some("Missing YPF filename key".into())))?;
        let name: Vec<_> = encoded.iter().map(|&byte| byte ^ key).collect();
        if checksum_scheme.filename(&name) != hash {
            return Err(corrupt(record_offset, "Filename hash mismatch"));
        }
        let name = encoding_rs::SHIFT_JIS
            .decode_without_bom_handling_and_without_replacement(&name)
            .ok_or_else(|| corrupt(record_offset, "Invalid CP932 filename"))?
            .into_owned();
        let file_type = reader.read_u8()?;
        let packing = reader.read_u8()?;
        if packing > 1 {
            return Err(Error::Unsupported(format!(
                "YPF compression method {packing}"
            )));
        }
        let unpacked_size = u64::from(reader.read_u32_le()?);
        let size = u64::from(reader.read_u32_le()?);
        let offset = if width == 4 {
            u64::from(reader.read_u32_le()?)
        } else {
            reader.read_u64_le()?
        };
        checksums.push(reader.read_u32_le()?);
        let kind = match file_type {
            0 => ResourceKind::Script,
            1..=4 | 7..=9 => ResourceKind::Image,
            5 | 6 => ResourceKind::Audio,
            _ => ResourceKind::Unknown,
        };
        let entry = Entry {
            name,
            kind,
            offset,
            size,
            packed: Some(Packed {
                unpacked_size,
                is_packed: packing == 1,
            }),
        };
        if offset < index_end || !entry.check_placement(source_len) {
            return Err(corrupt(
                record_offset,
                "Entry range lies outside the payload area",
            ));
        }
        if packing == 0 && size != unpacked_size {
            return Err(corrupt(record_offset, "Stored entry lengths disagree"));
        }
        entries.push(entry);
    }
    if reader.remaining() != 0 {
        return Err(corrupt(
            32 + reader.position() as u64,
            "Unexpected bytes after index records",
        ));
    }
    Ok(Index {
        entries,
        checksums,
        checksum_scheme,
        name_key: name_key.map(|key| Secret::new([key])),
    })
}

fn recover_name_key(
    index: &[u8],
    count: usize,
    layout: Layout,
    cancelled: Option<&AtomicBool>,
) -> Result<u8> {
    let Layout {
        swaps,
        width,
        checksum_scheme,
    } = layout;
    let mut candidates: Vec<u8> = (u8::MIN..=u8::MAX).collect();
    let mut reader = BinaryReader::new(index);
    for _ in 0..count {
        check_cancelled(cancelled)?;
        let offset = reader.position() as u64 + 32;
        let hash = reader.read_u32_le()?;
        let size = length(reader.read_u8()?, swaps);
        let encoded = reader.read_bytes(size)?;
        reader.read_bytes(14 + width)?;
        let mut plain = vec![0; encoded.len()];
        candidates.retain(|key| {
            for (out, byte) in plain.iter_mut().zip(encoded) {
                *out = *byte ^ key;
            }
            checksum_scheme.filename(&plain) == hash
        });
        match candidates.as_slice() {
            [key] => return Ok(*key),
            [] => {
                return Err(corrupt(
                    offset,
                    "No YPF filename key matches the stored hash",
                ));
            }
            _ => {}
        }
    }
    Err(Error::UnknownScheme(Some(
        "Ambiguous YPF filename key".into(),
    )))
}

/// Reads, checks and decompresses one requested entry using the scheme selected
/// by its index. Script encryption is a separate YSTB transform. Raw uncompressed
/// bytes borrow the supplied source; checksum failure never selects another scheme.
pub(super) fn read_entry<'a>(
    source: &'a dyn ReadAt,
    entry: &Entry,
    checksum: u32,
    checksum_scheme: ChecksumScheme,
) -> Result<Cow<'a, [u8]>> {
    let stored = source.read_at(
        entry.offset,
        usize::try_from(entry.size)
            .map_err(|_| corrupt(entry.offset, "Stored size exceeds address space"))?,
    )?;
    if checksum_scheme.payload(&stored) != checksum {
        return Err(corrupt(entry.offset, "Stored payload hash mismatch"));
    }
    if let Some(packed) = entry.packed.filter(|packed| packed.is_packed) {
        let expected = usize::try_from(packed.unpacked_size)
            .map_err(|_| corrupt(entry.offset, "Decoded size exceeds address space"))?;
        let decoded = zlib::inflate_with_limit(&stored, expected)
            .map_err(|error| corrupt(entry.offset, &error.to_string()))?;
        if decoded.len() != expected {
            return Err(corrupt(entry.offset, "Decompressed length mismatch"));
        }
        Ok(Cow::Owned(decoded))
    } else {
        Ok(stored)
    }
}

pub(super) struct YpfArchive {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
    checksums: Vec<u32>,
    checksum_scheme: ChecksumScheme,
    script_key: OnceLock<[u8; 4]>,
}

impl std::fmt::Debug for YpfArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YpfArchive")
            .field("view", &self.view)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl YpfArchive {
    pub(super) fn open(
        view: Arc<ArcView>,
        script_key: Option<[u8; 4]>,
        name_key: Option<u8>,
    ) -> Result<Self> {
        let index = read_index(&*view, name_key, None)?;
        let resolved_script_key = OnceLock::new();
        if let Some(key) = script_key {
            let _ = resolved_script_key.set(key);
        }
        Ok(Self {
            view,
            entries: index.entries,
            checksums: index.checksums,
            checksum_scheme: index.checksum_scheme,
            script_key: resolved_script_key,
        })
    }

    fn index(&self, entry: &Entry) -> Result<usize> {
        self.entries
            .iter()
            .position(|candidate| std::ptr::eq(candidate, entry))
            .or_else(|| {
                self.entries.iter().position(|candidate| {
                    candidate.offset == entry.offset
                        && candidate.name == entry.name
                        && candidate.size == entry.size
                })
            })
            .ok_or_else(|| corrupt(entry.offset, "Entry does not belong to this YPF"))
    }

    fn script_key(&self, current_ystb: &[u8]) -> Result<[u8; 4]> {
        if let Some(&key) = self.script_key.get() {
            return Ok(key);
        }
        let key = self.recover_script_key(current_ystb)?;
        let _ = self.script_key.set(key);
        Ok(key)
    }

    fn recover_script_key(&self, current_ystb: &[u8]) -> Result<[u8; 4]> {
        let ysc_index = self
            .entries
            .iter()
            .position(|entry| {
                entry
                    .name
                    .replace('\\', "/")
                    .eq_ignore_ascii_case("ysbin/ysc.ybn")
            })
            .ok_or_else(|| Error::UnknownScheme(Some("Missing identified YSTB key".into())))?;
        let ysc_bytes = read_entry(
            &*self.view,
            &self.entries[ysc_index],
            self.checksums[ysc_index],
            self.checksum_scheme,
        )?;
        let (definitions, _) = vnlens_script::yuris::commands(&ysc_bytes, None)?;
        let cancelled = AtomicBool::new(false);
        if let Some(secret) =
            vnlens_script::yuris::recover_ystb_key(current_ystb, &definitions, &cancelled)?
        {
            return <[u8; 4]>::try_from(secret.bytes())
                .map_err(|_| Error::UnknownScheme(Some("Invalid recovered YSTB key".into())));
        }
        let mut candidates: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                (index != ysc_index
                    && entry
                        .name
                        .rsplit_once('.')
                        .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("ybn")))
                .then_some(index)
            })
            .collect();
        candidates.sort_by_key(|&index| {
            let entry = &self.entries[index];
            std::cmp::Reverse(entry.packed.map_or(entry.size, |p| p.unpacked_size))
        });
        let mut evidence_error = None;
        for index in candidates {
            let result = read_entry(
                &*self.view,
                &self.entries[index],
                self.checksums[index],
                self.checksum_scheme,
            )
            .and_then(|data| {
                if !data.starts_with(b"YSTB") {
                    return Ok(None);
                }
                vnlens_script::yuris::recover_ystb_key(&data, &definitions, &cancelled)
            });
            match result {
                Ok(Some(secret)) => {
                    return <[u8; 4]>::try_from(secret.bytes()).map_err(|_| {
                        Error::UnknownScheme(Some("Invalid recovered YSTB key".into()))
                    });
                }
                Ok(None) => {}
                Err(error @ Error::UnknownScheme(_)) => return Err(error),
                Err(error) => {
                    evidence_error.get_or_insert(error);
                }
            }
        }
        if let Some(error) = evidence_error {
            return Err(error);
        }
        Err(Error::UnknownScheme(Some(
            "YU-RIS YSTB key could not be uniquely recovered from archive evidence".into(),
        )))
    }
}

impl Archive for YpfArchive {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn vnlens_io::ReadAt>>> {
        let index = self.index(entry)?;
        if entry
            .name
            .rsplit('.')
            .next()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("ybn"))
        {
            return Ok(None);
        }
        Ok(Some(Arc::new(super::stream::YpfSource {
            source: Arc::new(vnlens_io::RangeSource::new(
                self.view.clone(),
                entry.offset,
                entry.size,
            )?),
            packed: entry.packed.is_some_and(|packed| packed.is_packed),
            size: entry
                .packed
                .map_or(entry.size, |packed| packed.unpacked_size),
            checksum: self.checksums[index],
            checksum_scheme: self.checksum_scheme,
            offset: entry.offset,
        })))
    }
    fn virtual_paths(&self) -> Result<Vec<(usize, String)>> {
        let Some(table) = self.entries.iter().find(|entry| {
            entry
                .name
                .replace('\\', "/")
                .eq_ignore_ascii_case("ysbin/yst_list.ybn")
        }) else {
            return Ok(Vec::new());
        };
        let data = self.open_entry(table)?;
        let paths = vnlens_script::yuris::script_paths(&data)?;
        let indices: std::collections::HashMap<_, _> = self
            .entries
            .iter()
            .enumerate()
            .map(|(index, entry)| (entry.name.replace('\\', "/").to_ascii_lowercase(), index))
            .collect();
        Ok(paths
            .into_iter()
            .filter_map(|(id, path)| {
                indices
                    .get(&format!("ysbin/yst{id:05}.ybn"))
                    .filter(|_| !path.is_empty())
                    .map(|&index| (index, path))
            })
            .collect())
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let index = self.index(entry)?;
        let mut bytes = read_entry(
            &*self.view,
            entry,
            self.checksums[index],
            self.checksum_scheme,
        )?;
        if bytes.starts_with(b"YSTB") {
            let key = self.script_key(&bytes)?;
            vnlens_script::yuris::decrypt_ystb(bytes.to_mut(), &key)?;
        }
        Ok(bytes)
    }
}

fn corrupt(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "../../tests/yuris/ypf.rs"]
mod tests;
