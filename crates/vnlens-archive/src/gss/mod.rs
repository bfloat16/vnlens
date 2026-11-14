//! GSS LSDARC V.100: a BIN index with a 16-byte header and variable records
//! (LE flags, ARC offset, logical size, stored size, CP932 NUL name). Layout
//! follows DistortedCode sub_50720/sub_4FE10. ARC payloads remain lazy; storage
//! padding is retained by raw reads. Native names have no invented suffixes.
use std::{
    borrow::Cow,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use vnlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, Packed, ResourceKind, Result,
};
use vnlens_io::{ArcView, BinaryIo, BinaryReader, RangeSource, ReadAt};

struct Record {
    flags: u32,
    logical_size: u64,
}
#[derive(Debug, Default)]
struct LsdArc;
impl Format for LsdArc {
    fn tag(&self) -> &'static str {
        "lsdarc/gss"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0x4144_534c]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["bin"]
    }
    fn description(&self) -> &'static str {
        "GSS LSDARC paired index/data archive"
    }
}
impl ArchiveFormat for LsdArc {
    fn open(&self, view: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        let path = view.path();
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let stem = path
            .file_stem()
            .ok_or(Error::InvalidFormat)?
            .to_string_lossy();
        let mut data_path = parent.join(format!("{stem}.ARC"));
        if view
            .related_len(&data_path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            data_path = parent.join(format!("{stem}.arc"));
        }
        let source = view.related_source(&data_path)?;
        Ok(Box::new(Bank::open(
            view.slice(0, view.len())?,
            source,
            &stem,
        )?))
    }
}
vnlens_core::register_archive!(LsdArc);

struct Bank {
    source: Arc<dyn ReadAt>,
    entries: Vec<Entry>,
    records: Vec<Record>,
}
impl Bank {
    fn open(bytes: &[u8], source: Arc<dyn ReadAt>, bank: &str) -> Result<Self> {
        let mut reader = BinaryReader::new(bytes);
        let header = reader.read_bytes(12)?;
        if &header[..7] != b"LSDARC " {
            return Err(Error::InvalidFormat);
        }
        if &header[7..] != b"V.100" {
            return Err(Error::Unsupported("LSDARC index version".into()));
        }
        let count = reader.read_u32_le()?;
        if u64::from(count) * 17 > reader.remaining() as u64 {
            return Err(BinaryIo::unexpected_eof("LSDARC records exceed index").into());
        }
        let kind = match bank.to_ascii_uppercase().as_str() {
            "SCRDATA" => ResourceKind::Script,
            "WAVDATA" => ResourceKind::Audio,
            "BMPDATA" | "2BMPDATA" => ResourceKind::Image,
            "FONTDATA" => ResourceKind::Font,
            "VIBRATIONDATA" => ResourceKind::Data,
            _ => ResourceKind::Unknown,
        };
        let mut entries = Vec::new();
        let mut records = Vec::new();
        for _ in 0..count {
            let at = reader.position();
            let flags = reader.read_u32_le()?;
            let offset = u64::from(reader.read_u32_le()?);
            let logical_size = u64::from(reader.read_u32_le()?);
            let size = u64::from(reader.read_u32_le()?);
            let start = reader.position();
            while reader.read_u8()? != 0 {}
            let raw_name = &bytes[start..reader.position() - 1];
            let (name, invalid) = encoding_rs::SHIFT_JIS.decode_without_bom_handling(raw_name);
            if invalid {
                return Err(bad(start as u64, "Invalid LSDARC CP932 name"));
            }
            let entry = Entry {
                name: name.into_owned(),
                kind,
                offset,
                size,
                packed: (flags != 0).then_some(Packed {
                    unpacked_size: logical_size,
                    is_packed: true,
                }),
            };
            if !entry.check_placement(source.len()) {
                return Err(BinaryIo::unexpected_eof("LSDARC entry exceeds ARC storage").into());
            }
            if flags == 0 && logical_size > size {
                return Err(bad(at as u64, "LSDARC logical size exceeds stored size"));
            }
            entries.push(entry);
            records.push(Record {
                flags,
                logical_size,
            });
        }
        Ok(Self {
            source,
            entries,
            records,
        })
    }
    fn record(&self, entry: &Entry) -> Result<&Record> {
        self.entries
            .iter()
            .position(|stored| {
                stored.name == entry.name
                    && stored.offset == entry.offset
                    && stored.size == entry.size
            })
            .map(|index| &self.records[index])
            .ok_or_else(|| bad(entry.offset, "Entry does not belong to this LSDARC bank"))
    }
    fn read<'a>(&'a self, entry: &Entry, cancel: &AtomicBool) -> Result<Cow<'a, [u8]>> {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let record = self.record(entry)?;
        let bytes = self.source.read_at(
            entry.offset,
            usize::try_from(if record.flags == 0 {
                record.logical_size
            } else {
                entry.size
            })
            .map_err(|_| Error::Unsupported("LSDARC entry cannot fit in address space".into()))?,
        )?;
        if record.flags == 0 {
            return Ok(match bytes {
                Cow::Borrowed(bytes) => {
                    Cow::Borrowed(bytes.strip_prefix(b"BIN\x1a").unwrap_or(bytes))
                }
                Cow::Owned(mut bytes) => {
                    if bytes.starts_with(b"BIN\x1a") {
                        bytes.drain(..4);
                    }
                    Cow::Owned(bytes)
                }
            });
        }
        if BinaryReader::new(&bytes).read_bytes(4)? != b"LSD\x1a" {
            return Err(bad(entry.offset, "Invalid LSD compressed entry signature"));
        }
        let result = vnlens_crypto::compress::gss::decompress(
            &bytes[4..],
            usize::try_from(record.logical_size).map_err(|_| {
                Error::Unsupported("LSDARC logical entry cannot fit in address space".into())
            })?,
            cancel,
        );
        match result {
            Ok(bytes) => Ok(Cow::Owned(bytes)),
            Err(_) if cancel.load(Ordering::Relaxed) => Err(Error::Cancelled),
            Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {
                Err(Error::Unsupported(error.to_string()))
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                Err(bad(entry.offset, &error.to_string()))
            }
            Err(error) => Err(error.into()),
        }
    }
    fn source(&self, entry: &Entry, cancel: &AtomicBool) -> Result<Arc<dyn ReadAt>> {
        let record = self.record(entry)?;
        if record.flags != 0 {
            return Ok(Arc::new(Arc::<[u8]>::from(
                self.read(entry, cancel)?.into_owned(),
            )));
        }
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let skip = if record.logical_size >= 4
            && self.source.read_at(entry.offset, 4)?.as_ref() == b"BIN\x1a"
        {
            4
        } else {
            0
        };
        Ok(Arc::new(RangeSource::new(
            self.source.clone(),
            entry.offset + skip,
            record.logical_size - skip,
        )?))
    }
}
impl Archive for Bank {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        self.read(entry, &AtomicBool::new(false))
    }
    fn open_entry_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        self.record(entry)?;
        Ok(self.source.read_at(
            entry.offset,
            usize::try_from(entry.size).map_err(|_| {
                Error::Unsupported("LSDARC stored entry cannot fit in address space".into())
            })?,
        )?)
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn ReadAt>>> {
        self.source(entry, &AtomicBool::new(false)).map(Some)
    }
    fn open_entry_source_cancellable(
        &self,
        entry: &Entry,
        cancel: &AtomicBool,
    ) -> Result<Option<Arc<dyn ReadAt>>> {
        self.source(entry, cancel).map(Some)
    }
}
fn bad(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "../../tests/gss/mod.rs"]
mod tests;
