//! CPK/TOC/ITOC: 0x10-byte LE packet headers contain BE @UTF metadata.
//! TOC offsets are relative to min(ContentOffset, TocOffset); ITOC-only banks
//! store IDs in ascending order with CPK alignment. Entry payloads are lazy;
//! CRILAYLA is applied only to the selected entry with differing stored size.
use super::{add, bounds, corrupt, memory, range, utf::Table};
use std::{borrow::Cow, collections::BTreeMap, sync::Arc};
use vnlens_core::{Entry, Error, Packed, ResourceKind, Result};
use vnlens_crypto::compress::crilayla;
use vnlens_io::{BinaryReader, ReadAt};

pub struct Cpk {
    pub entries: Vec<Entry>,
    pub header: Arc<Table>,
    pub toc: Option<Arc<Table>>,
    pub itoc: Option<Arc<Table>>,
    source: Arc<dyn ReadAt>,
}
impl std::fmt::Debug for Cpk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cpk")
            .field("entries", &self.entries)
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}
impl Cpk {
    pub fn open(source: Arc<dyn ReadAt>) -> Result<Self> {
        let header = Arc::new(packet(source.clone(), 0, b"CPK ")?);
        if header.row_count != 1 {
            return Err(corrupt(0, "CPK header must contain one row"));
        }
        let content = number(&header, 0, "ContentOffset")?;
        bounds(source.as_ref(), content, 0)?;
        let toc_offset = header.number(0, "TocOffset")?.unwrap_or(0);
        let itoc_offset = header.number(0, "ItocOffset")?.unwrap_or(0);
        let mut entries = Vec::new();
        let mut toc = None;
        let mut itoc = None;
        if toc_offset != 0 {
            let table = Arc::new(packet(source.clone(), toc_offset, b"TOC ")?);
            let base = content.min(toc_offset);
            for row in 0..table.row_count {
                let filename = table
                    .value(row, "FileName")?
                    .and_then(|v| v.text().map(str::to_owned))
                    .ok_or_else(|| corrupt(toc_offset, "CPK TOC has no filename"))?;
                let directory = table
                    .value(row, "DirName")?
                    .and_then(|v| v.text().map(str::to_owned))
                    .unwrap_or_default();
                let name = if directory.is_empty() {
                    filename
                } else {
                    format!("{directory}/{filename}")
                };
                entries.push(entry(
                    name,
                    add(base, number(&table, row, "FileOffset")?)?,
                    &table,
                    row,
                    source.as_ref(),
                )?);
            }
            toc = Some(table);
        } else if itoc_offset != 0 {
            let table = Arc::new(packet(source.clone(), itoc_offset, b"ITOC")?);
            if table.row_count != 1 {
                return Err(corrupt(itoc_offset, "CPK ITOC header must contain one row"));
            }
            let mut records = BTreeMap::new();
            for column in ["DataL", "DataH"] {
                if let Some(data) = table.binary(0, column)? {
                    let ids = Table::open(data)?;
                    for row in 0..ids.row_count {
                        let id = number(&ids, row, "ID")?;
                        if records
                            .insert(
                                id,
                                (
                                    number(&ids, row, "FileSize")?,
                                    ids.number(row, "ExtractSize")?,
                                ),
                            )
                            .is_some()
                        {
                            return Err(corrupt(itoc_offset, "Duplicate CPK ITOC ID"));
                        }
                    }
                }
            }
            let alignment = header.number(0, "Align")?.unwrap_or(1);
            if alignment == 0 {
                return Err(corrupt(0, "CPK alignment is zero"));
            }
            let mut offset = content;
            for (id, (size, unpacked)) in records {
                bounds(source.as_ref(), offset, size)?;
                entries.push(Entry {
                    name: id.to_string(),
                    offset,
                    size,
                    kind: ResourceKind::Unknown,
                    packed: packed(size, unpacked.unwrap_or(size)),
                });
                offset = align(add(offset, size)?, alignment)?;
            }
            itoc = Some(table);
        } else if header.number(0, "Files")?.unwrap_or(0) != 0 {
            return Err(Error::Unsupported(
                "CPK has no supported TOC or ITOC index".into(),
            ));
        }
        if let Some(files) = header.number(0, "Files")?
            && files != entries.len() as u64
        {
            return Err(corrupt(0, "CPK file count differs from its index"));
        }
        Ok(Self {
            entries,
            source,
            header,
            toc,
            itoc,
        })
    }
    pub fn read_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(self.source.read_at(entry.offset, memory(entry.size)?)?)
    }
    pub fn read(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        let bytes = self.read_raw(entry)?;
        if let Some(packed) = entry.packed {
            let output = crilayla::decompress(&bytes, memory(packed.unpacked_size)?)
                .map_err(|error| corrupt(entry.offset, format!("CPK {}: {error}", entry.name)))?;
            Ok(Cow::Owned(output))
        } else {
            Ok(bytes)
        }
    }
    pub fn source(&self, entry: &Entry) -> Result<Arc<dyn ReadAt>> {
        if entry.packed.is_some() {
            Ok(Arc::new(Arc::<[u8]>::from(self.read(entry)?.into_owned())))
        } else {
            range(self.source.clone(), entry.offset, entry.size)
        }
    }
}
fn number(table: &Table, row: u32, name: &str) -> Result<u64> {
    table
        .number(row, name)?
        .ok_or_else(|| corrupt(0, format!("Missing CPK field {name}")))
}
fn packed(size: u64, unpacked: u64) -> Option<Packed> {
    (size != unpacked).then_some(Packed {
        unpacked_size: unpacked,
        is_packed: true,
    })
}
fn entry(name: String, offset: u64, table: &Table, row: u32, source: &dyn ReadAt) -> Result<Entry> {
    let size = number(table, row, "FileSize")?;
    bounds(source, offset, size)?;
    Ok(Entry {
        name,
        kind: ResourceKind::Unknown,
        offset,
        size,
        packed: packed(size, table.number(row, "ExtractSize")?.unwrap_or(size)),
    })
}
fn packet(source: Arc<dyn ReadAt>, offset: u64, tag: &[u8; 4]) -> Result<Table> {
    let header = source.read_at(offset, 16)?;
    if &header[..4] != tag {
        return Err(Error::InvalidFormat);
    }
    let size = BinaryReader::u64_le(&header[8..16]);
    Table::open(range(source.clone(), add(offset, 16)?, size)?)
}
pub(super) fn align(offset: u64, alignment: u64) -> Result<u64> {
    let padding = (alignment - offset % alignment) % alignment;
    add(offset, padding)
}

#[cfg(test)]
#[path = "../../tests/criware/cpk.rs"]
mod tests;
