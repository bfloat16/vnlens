//! BGI resource archives. sub_140039570 loads the little-endian 16-byte header
//! and either 0x20-byte PackFile or 0x80-byte ARC20 records. Data offsets are
//! relative to the end of the index. Names are preserved rather than applying
//! the runtime's case folding. Payload transforms are deferred until access.

use std::{borrow::Cow, sync::Arc};
use vnlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, ResourceKind, Result,
};
use vnlens_io::{ArcView, BinaryReader};

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
        let index_size = u64::from(header.count)
            .checked_mul(header.record_size)
            .ok_or_else(|| Error::Corrupt {
                offset: 12,
                reason: "BGI index size overflow".into(),
            })?;
        let base = 16u64
            .checked_add(index_size)
            .ok_or_else(|| Error::Corrupt {
                offset: 12,
                reason: "BGI data base overflow".into(),
            })?;
        let mut reader = BinaryReader::new(view.slice(16, index_size)?);
        let mut entries = Vec::new();
        for _ in 0..header.count {
            let record_offset = 16 + reader.position() as u64;
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
                    offset: record_offset,
                    reason: "Invalid BGI CP932 entry name".into(),
                });
            }
            let offset = base
                .checked_add(u64::from(record.read_u32_le()?))
                .ok_or_else(|| Error::Corrupt {
                    offset: record_offset,
                    reason: "BGI entry offset overflow".into(),
                })?;
            let entry = Entry {
                kind: ResourceKind::Unknown,
                name: name.into_owned(),
                offset,
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
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn vnlens_io::ReadAt>>> {
        // DCProcPlayMovieByMF (sub_1400F22B0) resolves an ARC entry to its
        // stored range. YCArchiveStream::Read (sub_1401026D0) passes those
        // bytes unchanged to Media Foundation (sub_140110A60).
        let header = self.view.slice(entry.offset, entry.size.min(16))?;
        if header.starts_with(b"DSC FORMAT 1.00\0")
            || matches!(header.get(4..8), Some(b"bw  " | b"hw  "))
        {
            return Ok(None);
        }
        Ok(Some(Arc::new(vnlens_io::RangeSource::new(
            self.view.clone(),
            entry.offset,
            entry.size,
        )?)))
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let bytes = self.view.slice(entry.offset, entry.size)?;
        if bytes.starts_with(b"DSC FORMAT 1.00\0") {
            let decoded = vnlens_crypto::compress::bgi::dsc(bytes).map_err(|error| {
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
        if let Some(payload) = vnlens_audio::bgi::ogg_payload(bytes)? {
            return Ok(Cow::Borrowed(payload));
        }
        Ok(Cow::Borrowed(bytes))
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.view.slice(entry.offset, entry.size)?))
    }
}

vnlens_core::register_archive!(BgiArchiveFormat);

#[cfg(test)]
#[path = "../../tests/bgi/mod.rs"]
mod tests;
