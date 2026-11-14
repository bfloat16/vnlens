//! CL3 section container, following Otomate's sub_10DF20/sub_10E000 and
//! sub_123CB0. CL3L/CL3B select integer byte order. Section records are 0x50
//! bytes; FILE_COLLECTION records are 0x230 bytes, with absolute stored ranges
//! relative to their section base. FILE_LINK and unknown sections stay intact.
use std::{borrow::Cow, sync::Arc};
use vnlens_core::{
    Archive, ArchiveFormat, ArchiveOptions, Entry, Error, Format, ResourceKind, Result,
};
use vnlens_io::{ArcView, BinaryIo, Endian, RangeSource, ReadAt};

const SIGNATURES: &[u32] = &[0x4c33_4c43, 0x4233_4c43];

/// Original section descriptors. Payloads, including FILE_LINK, are read only
/// when selected through their source range; the index does not preload them.
#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub count: u32,
    pub size: u64,
    pub offset: u64,
    pub raw: Vec<u8>,
}

#[derive(Debug)]
pub struct Index {
    pub header: Vec<u8>,
    pub sections: Vec<Section>,
    pub records: Vec<Vec<u8>>,
}

#[derive(Debug, Default)]
struct Cl3;
impl Format for Cl3 {
    fn tag(&self) -> &'static str {
        "cl3/otomate"
    }
    fn signatures(&self) -> &'static [u32] {
        SIGNATURES
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["cl3"]
    }
    fn description(&self) -> &'static str {
        "Otomate CL3 file collection"
    }
}
impl ArchiveFormat for Cl3 {
    fn open(&self, view: &Arc<ArcView>, _: &ArchiveOptions) -> Result<Box<dyn Archive>> {
        Ok(Box::new(Collection::open(view.clone())?))
    }
    fn open_source(
        &self,
        source: Arc<dyn ReadAt>,
        _: &str,
        _: &ArchiveOptions,
    ) -> Result<Option<Box<dyn Archive>>> {
        Ok(Some(Box::new(Collection::open(source)?)))
    }
}
vnlens_core::register_archive!(Cl3);

struct Collection {
    source: Arc<dyn ReadAt>,
    entries: Vec<Entry>,
    index: Arc<Index>,
}
impl Collection {
    fn open(source: Arc<dyn ReadAt>) -> Result<Self> {
        let header = source.read_at(0, 0x40)?.into_owned();
        let endian = match &header[..4] {
            b"CL3L" => Endian::Little,
            b"CL3B" => Endian::Big,
            _ => return Err(Error::InvalidFormat),
        };
        let count = endian.read_u32(&header[0xc..]);
        let table = u64::from(endian.read_u32(&header[0x10..]));
        bounds(source.as_ref(), table, u64::from(count) * 0x50)?;
        let mut sections = Vec::new();
        let mut entries = Vec::new();
        let mut records = Vec::new();
        for i in 0..count {
            let at = table + u64::from(i) * 0x50;
            let raw = source.read_at(at, 0x50)?.into_owned();
            let section = Section {
                name: name(&raw[..0x20], at)?,
                count: endian.read_u32(&raw[0x20..]),
                size: u64::from(endian.read_u32(&raw[0x24..])),
                offset: u64::from(endian.read_u32(&raw[0x28..])),
                raw,
            };
            bounds(source.as_ref(), section.offset, section.size)?;
            if section.name == "FILE_COLLECTION" {
                let table_size = u64::from(section.count) * 0x230;
                if table_size > section.size {
                    return Err(bad(at + 0x20, "CL3 file records exceed section"));
                }
                for j in 0..section.count {
                    let row = section.offset + u64::from(j) * 0x230;
                    let raw = source.read_at(row, 0x230)?.into_owned();
                    let relative = u64::from(endian.read_u32(&raw[0x204..]));
                    let size = u64::from(endian.read_u32(&raw[0x208..]));
                    if relative > section.size || size > section.size - relative {
                        return Err(bad(row + 0x204, "CL3 file range exceeds collection"));
                    }
                    entries.push(Entry {
                        name: name(&raw[..0x200], row)?,
                        offset: section.offset + relative,
                        size,
                        kind: ResourceKind::Unknown,
                        packed: None,
                    });
                    records.push(raw);
                }
            }
            sections.push(section);
        }
        Ok(Self {
            source,
            entries,
            index: Arc::new(Index {
                header,
                sections,
                records,
            }),
        })
    }
}
impl Archive for Collection {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
    fn metadata(&self) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        Some(self.index.clone())
    }
    fn open_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(self.source.read_at(
            entry.offset,
            usize::try_from(entry.size)
                .map_err(|_| bad(entry.offset, "CL3 entry exceeds address space"))?,
        )?)
    }
    fn open_entry_source(&self, entry: &Entry) -> Result<Option<Arc<dyn ReadAt>>> {
        Ok(Some(Arc::new(RangeSource::new(
            self.source.clone(),
            entry.offset,
            entry.size,
        )?)))
    }
}
fn bounds(source: &dyn ReadAt, offset: u64, size: u64) -> Result<()> {
    if offset > source.len() || size > source.len() - offset {
        return Err(BinaryIo::unexpected_eof("CL3 range exceeds source").into());
    }
    Ok(())
}
fn name(bytes: &[u8], offset: u64) -> Result<String> {
    let bytes = &bytes[..bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len())];
    let (name, _, invalid) = encoding_rs::SHIFT_JIS.decode(bytes);
    if invalid {
        return Err(bad(offset, "Invalid CL3 CP932 name"));
    }
    Ok(name.into_owned())
}
fn bad(offset: u64, reason: &str) -> Error {
    Error::Corrupt {
        offset,
        reason: reason.into(),
    }
}

#[cfg(test)]
#[path = "../../tests/otomate/mod.rs"]
mod tests;
