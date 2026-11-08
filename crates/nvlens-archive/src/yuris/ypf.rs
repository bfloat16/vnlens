//! YPF 0x1EE, verified against client index reader 0x45EC64 and entry reader
//! 0x43F0C8. The header's index end includes its 0x20 bytes. Records contain
//! MurmurHash2 name hashes, substituted name lengths, XOR names, type/packing,
//! unpacked/stored lengths, a 64-bit file offset, and a stored-byte hash.

use nvlens_core::{ArcView, Archive, Entry, Error, Packed, ResourceKind, Result};
use nvlens_crypto::{compress::zlib, hash::murmur2};
use nvlens_io::BinaryReader;
use std::borrow::Cow;
use std::sync::Arc;

// Client 0x46327C constructs this involution before decoding index lengths.
const LENGTH_SWAPS: &[(u8, u8)] = &[
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

pub(super) struct YpfArchive {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
    checksums: Vec<u32>,
    script_key: [u8; 4],
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
    pub(super) fn open(view: Arc<ArcView>, script_key: [u8; 4], name_key: u8) -> Result<Self> {
        let header = view.slice(0, 32)?;
        let version = BinaryReader::u32_le(&header[4..]);
        if version != 0x1ee {
            return Err(Error::Unsupported(format!("YPF version 0x{version:X}")));
        }
        let count = BinaryReader::u32_le(&header[8..]) as usize;
        let index_end = u64::from(BinaryReader::u32_le(&header[12..]));
        let index_size = index_end
            .checked_sub(32)
            .ok_or_else(|| corrupt(12, "Index end precedes header"))?;
        let index = view.slice(32, index_size)?;
        if count > index.len() / 27 {
            return Err(corrupt(8, "Entry count exceeds index record capacity"));
        }
        let mut reader = BinaryReader::new(index);
        let mut entries = Vec::with_capacity(count);
        let mut checksums = Vec::with_capacity(count);
        for _ in 0..count {
            let record_offset = reader.position() as u64 + 32;
            let hash = reader.read_u32_le()?;
            let mut length = !reader.read_u8()?;
            for &(left, right) in LENGTH_SWAPS {
                if length == left {
                    length = right;
                    break;
                }
                if length == right {
                    length = left;
                    break;
                }
            }
            let encoded = reader.read_bytes(usize::from(length))?;
            let name_bytes: Vec<_> = encoded.iter().map(|&b| b ^ name_key).collect();
            if murmur2::hash(&name_bytes, 0) != hash {
                return Err(corrupt(record_offset, "Filename hash mismatch"));
            }
            let name = encoding_rs::SHIFT_JIS
                .decode_without_bom_handling_and_without_replacement(&name_bytes)
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
            let offset = reader.read_u64_le()?;
            checksums.push(reader.read_u32_le()?);
            let kind = match file_type {
                0 => ResourceKind::Script,
                1..=4 | 7..=9 => ResourceKind::Image,
                5 | 6 => ResourceKind::Audio,
                _ => ResourceKind::guess_from_name(&name),
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
            if offset < index_end || !entry.check_placement(view.len()) {
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
        Ok(Self {
            view,
            entries,
            checksums,
            script_key,
        })
    }
}

impl Archive for YpfArchive {
    fn entries(&self) -> &[Entry] {
        &self.entries
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
        let paths = nvlens_script::yuris::script_paths(&data)?;
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
        let index = self
            .entries
            .iter()
            .position(|candidate| std::ptr::eq(candidate, entry))
            .or_else(|| {
                self.entries.iter().position(|candidate| {
                    candidate.offset == entry.offset
                        && candidate.name == entry.name
                        && candidate.size == entry.size
                })
            })
            .ok_or_else(|| corrupt(entry.offset, "Entry does not belong to this archive"))?;
        let stored = self.view.slice(entry.offset, entry.size)?;
        if murmur2::hash(stored, 0) != self.checksums[index] {
            return Err(corrupt(entry.offset, "Stored payload hash mismatch"));
        }
        let packed = self.entries[index].packed;
        let mut bytes = if let Some(packed) = packed.filter(|p| p.is_packed) {
            let expected = usize::try_from(packed.unpacked_size)
                .map_err(|_| corrupt(entry.offset, "Decoded length exceeds address space"))?;
            let decoded = zlib::inflate_with_limit(stored, expected)
                .map_err(|e| corrupt(entry.offset, &e.to_string()))?;
            if decoded.len() != expected {
                return Err(corrupt(entry.offset, "Decompressed length mismatch"));
            }
            Cow::Owned(decoded)
        } else {
            Cow::Borrowed(stored)
        };
        if bytes.starts_with(b"YSTB") {
            nvlens_script::yuris::decrypt_ystb(bytes.to_mut(), &self.script_key)?;
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    struct TestFile(std::path::PathBuf);
    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    fn file(bytes: &[u8]) -> TestFile {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "nvlens-ypf-{}-{}-{}.ypf",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, bytes).unwrap();
        TestFile(path)
    }
    const RECORDS: &[(&str, &[u8], u8)] = &[("bad.ybn", b"x", 1), ("folder/ok.txt", b"hello", 0)];
    fn fixture(records: &[(&str, &[u8], u8)]) -> Vec<u8> {
        let index_end = 32
            + records
                .iter()
                .map(|(name, _, _)| 27 + name.len())
                .sum::<usize>();
        let mut bytes = vec![0; 32];
        bytes[..4].copy_from_slice(b"YPF\0");
        for (offset, value) in [
            (4, 0x1ee),
            (8, records.len() as u32),
            (12, index_end as u32),
        ] {
            BinaryWriter::u32_le(value, &mut bytes[offset..]);
        }
        let mut offset = index_end as u64;
        for (name, data, packed) in records {
            let mut record = vec![0; 27 + name.len()];
            BinaryWriter::u32_le(murmur2::hash(name.as_bytes(), 0), &mut record);
            let mut length = name.len() as u8;
            for &(a, b) in LENGTH_SWAPS {
                if length == a {
                    length = b;
                    break;
                }
                if length == b {
                    length = a;
                    break;
                }
            }
            record[4] = !length;
            for (out, &byte) in record[5..5 + name.len()].iter_mut().zip(name.as_bytes()) {
                *out = byte ^ 0xa7;
            }
            let at = 5 + name.len();
            record[at] = 0;
            record[at + 1] = *packed;
            BinaryWriter::u32_le(data.len() as u32, &mut record[at + 2..]);
            BinaryWriter::u32_le(data.len() as u32, &mut record[at + 6..]);
            BinaryWriter::u64_le(offset, &mut record[at + 10..]);
            BinaryWriter::u32_le(murmur2::hash(data, 0), &mut record[at + 18..]);
            offset += data.len() as u64;
            bytes.extend(record);
        }
        for (_, data, _) in records {
            bytes.extend_from_slice(data);
        }
        bytes
    }
    #[test]
    fn index_mount_is_lazy_and_identified_name_key_is_verified() {
        let bytes = fixture(RECORDS);
        let file = file(&bytes);
        let archive =
            YpfArchive::open(Arc::new(ArcView::open(&file.0).unwrap()), [0; 4], 0xa7).unwrap();
        assert_eq!(archive.entries()[1].name, "folder/ok.txt");
        assert_eq!(
            &*archive.open_entry(&archive.entries()[1]).unwrap(),
            b"hello"
        );
        assert!(archive.open_entry(&archive.entries()[0]).is_err());
        assert_eq!(
            &*archive.open_entry_raw(&archive.entries()[0]).unwrap(),
            b"x"
        );
        drop(archive);
    }
    #[test]
    fn rejects_truncated_index_and_out_of_range_64_bit_offsets() {
        let mut bytes = fixture(RECORDS);
        let first_offset = 32 + 5 + "bad.ybn".len() + 10;
        BinaryWriter::u64_le(0x1_0000_0000, &mut bytes[first_offset..]);
        let file = file(&bytes);
        assert!(YpfArchive::open(Arc::new(ArcView::open(&file.0).unwrap()), [0; 4], 0xa7).is_err());
        fs::write(&file.0, &bytes[..40]).unwrap();
        assert!(YpfArchive::open(Arc::new(ArcView::open(&file.0).unwrap()), [0; 4], 0xa7).is_err());
    }

    #[test]
    fn virtual_paths_read_only_the_script_list_and_preserve_entry_names() {
        let path = b"story\\main.yst";
        let mut table = vec![0; 20];
        table[..4].copy_from_slice(b"YSTL");
        BinaryWriter::u32_le(0x1ee, &mut table[4..]);
        BinaryWriter::u32_le(1, &mut table[8..]);
        BinaryWriter::u32_le(3, &mut table[12..]);
        BinaryWriter::u32_le(path.len() as u32, &mut table[16..]);
        table.extend_from_slice(path);
        table.resize(table.len() + 20, 0);
        let mut bytes = fixture(&[
            ("ysbin/yst00003.ybn", b"x", 1),
            ("ysbin/yst00004.ybn", b"other", 0),
            ("ysbin/yst_list.ybn", &table, 0),
        ]);
        let file = file(&bytes);
        let archive =
            YpfArchive::open(Arc::new(ArcView::open(&file.0).unwrap()), [0; 4], 0xa7).unwrap();
        assert_eq!(archive.entries()[0].name, "ysbin/yst00003.ybn");
        assert_eq!(
            archive.virtual_paths().unwrap(),
            [(0, "story\\main.yst".into())]
        );
        assert!(archive.open_entry(&archive.entries()[0]).is_err());
        drop(archive);
        let table_offset = bytes.len() - table.len();
        bytes[table_offset] = b'X';
        fs::write(&file.0, bytes).unwrap();
        let archive =
            YpfArchive::open(Arc::new(ArcView::open(&file.0).unwrap()), [0; 4], 0xa7).unwrap();
        assert_eq!(archive.entries().len(), 3);
        assert!(archive.virtual_paths().is_err());
    }
}
