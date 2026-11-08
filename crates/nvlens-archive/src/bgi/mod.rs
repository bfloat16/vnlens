//! BGI resource archives. sub_140039570 loads the little-endian 16-byte header
//! and either 0x20-byte PackFile or 0x80-byte ARC20 records. Data offsets are
//! relative to the end of the index. Names are preserved rather than applying
//! the runtime's case folding. Payload transforms are deferred until access.

use nvlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, ResourceKind, Result,
};
use nvlens_io::{ArcView, BinaryReader};
use std::{borrow::Cow, sync::Arc};

const SIGNATURES: &[u32] = &[0x4952_5542, 0x6b63_6150];

#[derive(Debug, Default)]
struct BgiArchiveFormat;

impl Format for BgiArchiveFormat {
    fn tag(&self) -> &'static str {
        "arc/bgi"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["arc"]
    }
    fn description(&self) -> &'static str {
        "BGI/Ethornell PackFile and ARC20 archives"
    }
}

#[derive(Debug)]
struct Header {
    count: u32,
    record_size: u64,
    name_size: usize,
}

impl Header {
    fn parse(data: &[u8]) -> Result<Self> {
        let mut reader = BinaryReader::new(data);
        let (record_size, name_size) = match reader.read_bytes(12)? {
            b"BURIKO ARC20" => (0x80, 0x60),
            b"PackFile    " => (0x20, 0x10),
            _ => return Err(Error::InvalidFormat),
        };
        Ok(Self {
            count: reader.read_u32_le()?,
            record_size,
            name_size,
        })
    }
}

impl ArchiveFormat for BgiArchiveFormat {
    fn open(&self, view: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        let header = Header::parse(view.slice(0, 16)?)?;
        let index_size = u64::from(header.count) * header.record_size;
        let base = 16 + index_size;
        let mut reader = BinaryReader::new(view.slice(16, index_size)?);
        let mut entries = Vec::new();
        for _ in 0..header.count {
            let mut record = BinaryReader::new(reader.read_bytes(header.record_size as usize)?);
            let name = record.read_bytes(header.name_size)?;
            let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
            // sub_1400FA4C0/1400FA4D0 accept UTF-8 and legacy CP932 names.
            let (name, errors) = match std::str::from_utf8(name) {
                Ok(name) => (Cow::Borrowed(name), false),
                Err(_) => {
                    let (name, _, errors) = encoding_rs::SHIFT_JIS.decode(name);
                    (name, errors)
                }
            };
            if errors {
                return Err(Error::Corrupt {
                    offset: 16 + reader.position() as u64 - header.record_size,
                    reason: "Invalid BGI CP932 entry name".into(),
                });
            }
            let entry = Entry {
                kind: ResourceKind::guess_from_name(&name),
                name: name.into_owned(),
                offset: base + u64::from(record.read_u32_le()?),
                size: u64::from(record.read_u32_le()?),
                packed: None,
            };
            if !entry.check_placement(view.len()) {
                return Err(Error::Corrupt {
                    offset: entry.offset,
                    reason: "BGI entry lies outside archive".into(),
                });
            }
            entries.push(entry);
        }
        Ok(Box::new(BgiArchive {
            view: view.clone(),
            entries,
        }))
    }
}

#[derive(Debug)]
struct BgiArchive {
    view: Arc<ArcView>,
    entries: Vec<Entry>,
}

impl Archive for BgiArchive {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let bytes = self.view.slice(entry.offset, entry.size)?;
        if bytes.starts_with(b"DSC FORMAT 1.00\0") {
            let decoded = nvlens_crypto::compress::bgi::dsc(bytes).map_err(|error| {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    Error::Io(error)
                } else {
                    Error::Corrupt {
                        offset: entry.offset,
                        reason: format!("BGI DSC: {error}"),
                    }
                }
            })?;
            return Ok(Cow::Owned(decoded));
        }
        if let Some(payload) = nvlens_audio::bgi::ogg_payload(bytes)? {
            return Ok(Cow::Borrowed(payload));
        }
        Ok(Cow::Borrowed(bytes))
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
}

nvlens_core::register_archive!(BgiArchiveFormat);

#[cfg(test)]
mod tests {
    use super::*;
    use nvlens_io::BinaryWriter;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };
    struct Temp(std::path::PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    fn fixture(record: usize, name_size: usize) -> Result<Temp> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "nvlens-bgi-{}-{}-{}.arc",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| Error::Unsupported(e.to_string()))?
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut bytes = vec![0; 16 + 2 * record];
        bytes[..12].copy_from_slice(if record == 128 {
            b"BURIKO ARC20"
        } else {
            b"PackFile    "
        });
        BinaryWriter::u32_le(2, &mut bytes[12..]);
        for (i, (name, size, offset)) in [("ok.txt", 2, 0), ("bad.bin", 16, 2)]
            .into_iter()
            .enumerate()
        {
            let start = 16 + i * record;
            bytes[start..start + name.len()].copy_from_slice(name.as_bytes());
            BinaryWriter::u32_le(offset, &mut bytes[start + name_size..]);
            BinaryWriter::u32_le(size, &mut bytes[start + name_size + 4..]);
        }
        bytes.extend(b"okDSC FORMAT 1.00\0");
        fs::write(&path, bytes)?;
        Ok(Temp(path))
    }
    #[test]
    fn both_indices_are_lazy_and_corrupt_unused_content_does_not_block_mount() -> Result<()> {
        for (record, name_size) in [(128, 96), (32, 16)] {
            let temp = fixture(record, name_size)?;
            let view = Arc::new(ArcView::open(&temp.0)?);
            let arc = BgiArchiveFormat.open(&view, &ArchiveOptions::default())?;
            assert_eq!(arc.entries().len(), 2);
            assert_eq!(&*arc.open_entry(&arc.entries()[0])?, b"ok");
            assert!(matches!(
                arc.open_entry_raw(&arc.entries()[0])?,
                Cow::Borrowed(_)
            ));
            assert!(arc.open_entry(&arc.entries()[1]).is_err());
            assert_eq!(
                &*arc.open_entry_raw(&arc.entries()[1])?,
                b"DSC FORMAT 1.00\0"
            );
        }
        Ok(())
    }
}
