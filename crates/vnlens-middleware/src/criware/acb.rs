//! ACB cue sheets are @UTF Header tables. Binary columns retain their native
//! tables, waveform bank and stream-bank metadata. They are indexed as virtual
//! files, without reading AWB payloads or guessing external bank filenames.
use super::{
    corrupt, memory, range,
    utf::{Table, Value},
};
use std::{borrow::Cow, sync::Arc};
use vnlens_core::{Entry, Error, ResourceKind, Result};
use vnlens_io::ReadAt;

#[derive(Clone, Copy, Debug)]
pub enum TableKind {
    Acb,
    Utf,
}

pub struct Bank {
    pub table: Arc<Table>,
    pub entries: Vec<Entry>,
    original: Arc<dyn ReadAt>,
}
impl std::fmt::Debug for Bank {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CriBank")
            .field("table", &self.table)
            .field("entries", &self.entries)
            .finish_non_exhaustive()
    }
}
impl Bank {
    pub fn open(source: Arc<dyn ReadAt>, kind: TableKind) -> Result<Self> {
        let table = Arc::new(Table::open(source.clone())?);
        if matches!(kind, TableKind::Acb) && (table.name != "Header" || table.row_count != 1) {
            return Err(corrupt(0, "ACB must contain one Header row"));
        }
        let mut entries = Vec::new();
        for row in 0..table.row_count {
            for column in &table.columns {
                if column.kind != 11 {
                    continue;
                }
                if let Some(Value::Data { offset, size }) = table.value(row, &column.name)?
                    && size != 0
                {
                    let leaf = if column.name == "AwbFile" {
                        "AwbFile.awb".into()
                    } else if column.name.ends_with("Table") {
                        format!("{}.utf", column.name)
                    } else {
                        column.name.clone()
                    };
                    let name = if table.row_count == 1 {
                        leaf
                    } else {
                        format!("{row}/{leaf}")
                    };
                    let kind = if column.name == "AwbFile" || column.name.ends_with("Table") {
                        ResourceKind::Archive
                    } else {
                        ResourceKind::Data
                    };
                    entries.push(Entry {
                        name,
                        offset,
                        size,
                        kind,
                        packed: None,
                    });
                }
            }
        }
        Ok(Self {
            table,
            entries,
            original: source,
        })
    }
    /// Opens a native subtable only when its consumer requests it.
    pub fn table(&self, row: u32, column: &str) -> Result<Option<Arc<Table>>> {
        self.table
            .binary(row, column)?
            .map(Table::open)
            .transpose()
            .map(|table| table.map(Arc::new))
    }
    pub fn read(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(self
            .table
            .source
            .read_at(entry.offset, memory(entry.size)?)?)
    }
    pub fn read_raw(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        Ok(self.original.read_at(entry.offset, memory(entry.size)?)?)
    }
    pub fn source(&self, entry: &Entry) -> Result<Arc<dyn ReadAt>> {
        range(self.table.source.clone(), entry.offset, entry.size)
    }
    pub fn cue_count(&self) -> Result<u32> {
        self.table(0, "CueTable")?
            .map(|table| table.row_count)
            .ok_or(Error::InvalidFormat)
    }
}

#[cfg(test)]
#[path = "../../tests/criware/acb.rs"]
mod tests;
