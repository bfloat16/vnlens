//! @UTF: 0x20-byte BE header, typed column schema, fixed-width rows, NUL
//! string pool and binary pool. All offsets except schema start are relative
//! to byte 8. Version and raw flags/types/string pool are retained. Default
//! values take priority over row values for the legacy 0x70 storage flag.
use super::{add, bounds, corrupt, memory, range, text};
use std::{borrow::Cow, io, sync::Arc};
use vnlens_core::{Error, Result};
use vnlens_crypto::cipher::criware::apply_utf;
use vnlens_io::{BinaryReader, ReadAt};

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Unsigned(u64),
    Signed(i64),
    Float(u32),
    Double(u64),
    String { offset: u32, text: String },
    Data { offset: u64, size: u64 },
    Guid([u8; 16]),
}
impl Value {
    #[must_use]
    pub fn unsigned(&self) -> Option<u64> {
        match self {
            Self::Unsigned(v) => Some(*v),
            Self::Signed(v) => u64::try_from(*v).ok(),
            _ => None,
        }
    }
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        match self {
            Self::String { text, .. } => Some(text),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Column {
    pub name: String,
    pub flags: u8,
    pub kind: u8,
    pub default: Option<Value>,
    row_offset: Option<usize>,
}

pub struct Table {
    pub name: String,
    pub version: u16,
    pub columns: Vec<Column>,
    pub row_count: u32,
    pub row_width: u16,
    pub strings: Arc<[u8]>,
    pub(super) source: Arc<dyn ReadAt>,
    rows: Arc<[u8]>,
    data_offset: u64,
}
impl std::fmt::Debug for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CriUtf")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("columns", &self.columns)
            .field("row_count", &self.row_count)
            .finish_non_exhaustive()
    }
}

impl Table {
    /// Reads schema, rows and strings, without reading binary pool payloads.
    pub fn open(mut source: Arc<dyn ReadAt>) -> Result<Self> {
        let magic = source.read_at(0, 4)?;
        if magic.as_ref() == [0x1f, 0x9e, 0xf3, 0xf5] {
            drop(magic);
            source = Arc::new(Encrypted { source });
        } else if magic.as_ref() != b"@UTF" {
            return Err(Error::InvalidFormat);
        }
        let header = source.read_at(0, 32)?;
        if &header[..4] != b"@UTF" {
            return Err(Error::InvalidFormat);
        }
        let size = add(8, u64::from(BinaryReader::u32_be(&header[4..8])))?;
        bounds(source.as_ref(), 0, size)?;
        let version = BinaryReader::u16_be(&header[8..10]);
        let rows_at = add(8, u64::from(BinaryReader::u16_be(&header[10..12])))?;
        let strings_at = add(8, u64::from(BinaryReader::u32_be(&header[12..16])))?;
        let data_at = add(8, u64::from(BinaryReader::u32_be(&header[16..20])))?;
        if !(32 <= rows_at && rows_at <= strings_at && strings_at <= data_at && data_at <= size) {
            return Err(corrupt(8, "Invalid UTF section ordering"));
        }
        let name_offset = BinaryReader::u32_be(&header[20..24]);
        let count = BinaryReader::u16_be(&header[24..26]);
        let row_width = BinaryReader::u16_be(&header[26..28]);
        let row_count = BinaryReader::u32_be(&header[28..32]);
        let rows_size = u64::from(row_width) * u64::from(row_count);
        if rows_size > strings_at - rows_at {
            return Err(corrupt(rows_at, "UTF rows overlap the string pool"));
        }
        let schema = source.read_at(32, memory(rows_at - 32)?)?;
        let strings: Arc<[u8]> = source
            .read_at(strings_at, memory(data_at - strings_at)?)?
            .as_ref()
            .into();
        let rows: Arc<[u8]> = source
            .read_at(rows_at, memory(strings_at - rows_at)?)?
            .as_ref()
            .into();
        let mut reader = BinaryReader::new(&schema);
        let mut columns = Vec::new();
        let mut row_offset = 0;
        for _ in 0..count {
            let flags = reader.read_u8()?;
            let kind = flags & 15;
            let name = string(&strings, BinaryReader::u32_be(reader.read_bytes(4)?))?;
            let width = width(kind)?;
            if flags & 0x80 != 0 {
                return Err(Error::Unsupported(format!("UTF storage flags {flags:#x}")));
            }
            let default = if flags & 0x20 != 0 {
                Some(value(
                    kind,
                    reader.read_bytes(width)?,
                    &strings,
                    data_at,
                    size,
                )?)
            } else {
                None
            };
            let offset = if flags & 0x20 == 0 && flags & 0x40 != 0 {
                let offset = row_offset;
                row_offset += width;
                Some(offset)
            } else {
                None
            };
            columns.push(Column {
                name,
                flags,
                kind,
                default,
                row_offset: offset,
            });
        }
        // SDK ACB files append runtime fields after the original row width.
        // The width remains the row stride; validate actual referenced fields
        // against the metadata region, including that final-row extension.
        if row_count != 0 {
            let end = u64::from(row_count - 1) * u64::from(row_width) + row_offset as u64;
            if end > strings_at - rows_at {
                return Err(corrupt(
                    rows_at,
                    "UTF row fields exceed the metadata region",
                ));
            }
        }
        let name = string(&strings, name_offset)?;
        drop(schema);
        drop(header);
        Ok(Self {
            name,
            version,
            columns,
            row_count,
            row_width,
            strings,
            source: range(source, 0, size)?,
            rows,
            data_offset: data_at,
        })
    }

    pub fn value(&self, row: u32, name: &str) -> Result<Option<Value>> {
        if row >= self.row_count {
            return Err(corrupt(u64::from(row), "UTF row index exceeds table"));
        }
        let Some(column) = self.columns.iter().find(|c| c.name == name) else {
            return Ok(None);
        };
        if let Some(default) = &column.default {
            return Ok(Some(default.clone()));
        }
        let zeros = [0; 16];
        let bytes = if let Some(offset) = column.row_offset {
            let at = memory(u64::from(row) * u64::from(self.row_width))? + offset;
            &self.rows[at..at + width(column.kind)?]
        } else {
            &zeros[..width(column.kind)?]
        };
        value(
            column.kind,
            bytes,
            &self.strings,
            self.data_offset,
            self.source.len(),
        )
        .map(Some)
    }

    pub fn number(&self, row: u32, name: &str) -> Result<Option<u64>> {
        self.value(row, name)?
            .map(|v| {
                v.unsigned().ok_or_else(|| {
                    corrupt(0, format!("UTF column {name} is not an unsigned integer"))
                })
            })
            .transpose()
    }

    pub fn binary(&self, row: u32, name: &str) -> Result<Option<Arc<dyn ReadAt>>> {
        match self.value(row, name)? {
            None => Ok(None),
            Some(Value::Data { size: 0, .. }) => Ok(None),
            Some(Value::Data { offset, size }) => {
                range(self.source.clone(), offset, size).map(Some)
            }
            _ => Err(corrupt(0, format!("UTF column {name} is not binary data"))),
        }
    }
}

fn string(pool: &[u8], offset: u32) -> Result<String> {
    let suffix = pool
        .get(offset as usize..)
        .ok_or_else(|| corrupt(u64::from(offset), "UTF string offset exceeds pool"))?;
    let end = suffix
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| corrupt(u64::from(offset), "Unterminated UTF string"))?;
    text(&suffix[..end])
}
fn width(kind: u8) -> Result<usize> {
    match kind {
        0 | 1 => Ok(1),
        2 | 3 => Ok(2),
        4 | 5 | 8 | 10 => Ok(4),
        6 | 7 | 9 | 11 => Ok(8),
        12 => Ok(16),
        _ => Err(Error::Unsupported(format!("UTF value type {kind}"))),
    }
}
fn value(kind: u8, bytes: &[u8], strings: &[u8], data: u64, total: u64) -> Result<Value> {
    Ok(match kind {
        0 => Value::Unsigned(u64::from(bytes[0])),
        1 => Value::Signed(i64::from(bytes[0] as i8)),
        2 => Value::Unsigned(u64::from(BinaryReader::u16_be(bytes))),
        3 => Value::Signed(i64::from(BinaryReader::u16_be(bytes) as i16)),
        4 => Value::Unsigned(u64::from(BinaryReader::u32_be(bytes))),
        5 => Value::Signed(i64::from(BinaryReader::u32_be(bytes) as i32)),
        6 => Value::Unsigned(BinaryReader::u64_be(bytes)),
        7 => Value::Signed(BinaryReader::u64_be(bytes) as i64),
        8 => Value::Float(BinaryReader::u32_be(bytes)),
        9 => Value::Double(BinaryReader::u64_be(bytes)),
        10 => {
            let offset = BinaryReader::u32_be(bytes);
            Value::String {
                offset,
                text: string(strings, offset)?,
            }
        }
        11 => {
            let offset = add(data, u64::from(BinaryReader::u32_be(bytes)))?;
            let size = u64::from(BinaryReader::u32_be(&bytes[4..]));
            if offset > total || size > total - offset {
                return Err(
                    vnlens_io::BinaryIo::unexpected_eof("UTF binary range exceeds table").into(),
                );
            }
            Value::Data { offset, size }
        }
        12 => Value::Guid(bytes.try_into().map_err(|_| Error::InvalidFormat)?),
        _ => return Err(Error::Unsupported(format!("UTF value type {kind}"))),
    })
}
struct Encrypted {
    source: Arc<dyn ReadAt>,
}
impl ReadAt for Encrypted {
    fn len(&self) -> u64 {
        self.source.len()
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        let mut bytes = self.source.read_at(offset, size)?.into_owned();
        apply_utf(offset, &mut bytes);
        Ok(Cow::Owned(bytes))
    }
}

#[cfg(test)]
#[path = "../../tests/criware/utf.rs"]
mod tests;
