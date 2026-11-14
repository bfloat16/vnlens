#![allow(clippy::unwrap_used)]
use super::*;
use std::{borrow::Cow, collections::BTreeMap, io, sync::Mutex};
use vnlens_io::BinaryWriter;

#[derive(Clone, Debug)]
pub enum Cell {
    Number(u64),
    Text(&'static str),
    Data(Vec<u8>),
}
pub fn table(name: &str, fields: &[(&str, u8, u8, Vec<Cell>)], rows: u32) -> Vec<u8> {
    let mut pool = vec![0];
    let mut names = BTreeMap::new();
    for text in std::iter::once(name)
        .chain(fields.iter().map(|f| f.0))
        .chain(fields.iter().flat_map(|f| f.3.iter()).filter_map(|v| {
            if let Cell::Text(s) = v {
                Some(*s)
            } else {
                None
            }
        }))
    {
        if !names.contains_key(text) {
            names.insert(text.to_owned(), pool.len() as u32);
            pool.extend_from_slice(text.as_bytes());
            pool.push(0);
        }
    }
    let mut binary = Vec::new();
    let mut encode = |kind: u8, value: &Cell| {
        let width = match kind {
            0 | 1 => 1,
            2 | 3 => 2,
            4 | 5 | 8 | 10 => 4,
            6 | 7 | 9 | 11 => 8,
            12 => 16,
            _ => 0,
        };
        let mut bytes = vec![0; width];
        match value {
            Cell::Number(n) => match width {
                1 => bytes[0] = *n as u8,
                2 => BinaryWriter::u16_be(*n as u16, &mut bytes),
                4 => BinaryWriter::u32_be(*n as u32, &mut bytes),
                8 => BinaryWriter::u64_be(*n, &mut bytes),
                _ => {}
            },
            Cell::Text(s) => BinaryWriter::u32_be(names[*s], &mut bytes),
            Cell::Data(data) => {
                BinaryWriter::u32_be(binary.len() as u32, &mut bytes);
                BinaryWriter::u32_be(data.len() as u32, &mut bytes[4..]);
                binary.extend_from_slice(data);
            }
        }
        bytes
    };
    let mut schema = Vec::new();
    for (name, kind, flags, values) in fields {
        schema.push(kind | flags);
        let mut offset = [0; 4];
        BinaryWriter::u32_be(names[*name], &mut offset);
        schema.extend_from_slice(&offset);
        if flags & 0x20 != 0 {
            schema.extend(encode(*kind, &values[0]));
        }
    }
    let mut row_bytes = Vec::new();
    for row in 0..rows as usize {
        for (_, kind, flags, values) in fields {
            if flags & 0x20 == 0 && flags & 0x40 != 0 {
                row_bytes.extend(encode(*kind, &values[row]));
            }
        }
    }
    let row_width = if rows == 0 {
        0
    } else {
        row_bytes.len() / rows as usize
    };
    let rows_at = 32 + schema.len();
    let strings_at = rows_at + row_bytes.len();
    let data_at = strings_at + pool.len();
    let mut out = vec![0; 32];
    out[..4].copy_from_slice(b"@UTF");
    BinaryWriter::u32_be((data_at + binary.len() - 8) as u32, &mut out[4..]);
    BinaryWriter::u16_be(1, &mut out[8..]);
    BinaryWriter::u16_be((rows_at - 8) as u16, &mut out[10..]);
    BinaryWriter::u32_be((strings_at - 8) as u32, &mut out[12..]);
    BinaryWriter::u32_be((data_at - 8) as u32, &mut out[16..]);
    BinaryWriter::u32_be(names[name], &mut out[20..]);
    BinaryWriter::u16_be(fields.len() as u16, &mut out[24..]);
    BinaryWriter::u16_be(row_width as u16, &mut out[26..]);
    BinaryWriter::u32_be(rows, &mut out[28..]);
    out.extend(schema);
    out.extend(row_bytes);
    out.extend(pool);
    out.extend(binary);
    out
}
pub fn source(bytes: Vec<u8>) -> Arc<dyn ReadAt> {
    Arc::new(Arc::<[u8]>::from(bytes))
}
#[derive(Debug)]
pub struct Watched {
    pub bytes: Vec<u8>,
    pub end: u64,
    pub reads: Mutex<Vec<(u64, usize)>>,
}
impl ReadAt for Watched {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        self.reads.lock().unwrap().push((offset, size));
        if offset > self.end || size as u64 > self.end - offset {
            return Err(io::Error::other("payload read forbidden during mount"));
        }
        Ok(Cow::Borrowed(
            &self.bytes[offset as usize..offset as usize + size],
        ))
    }
}
pub fn packet(tag: &[u8; 4], table: Vec<u8>) -> Vec<u8> {
    let mut bytes = vec![0; 16];
    bytes[..4].copy_from_slice(tag);
    BinaryWriter::u32_le(0xff, &mut bytes[4..]);
    BinaryWriter::u64_le(table.len() as u64, &mut bytes[8..]);
    bytes.extend(table);
    bytes
}
pub fn awb() -> Vec<u8> {
    let mut bytes = vec![0; 68];
    bytes[..4].copy_from_slice(b"AFS2");
    bytes[4] = 2;
    bytes[5] = 4;
    BinaryWriter::u16_le(2, &mut bytes[6..]);
    BinaryWriter::u32_le(2, &mut bytes[8..]);
    BinaryWriter::u16_le(16, &mut bytes[12..]);
    BinaryWriter::u16_le(123, &mut bytes[14..]);
    BinaryWriter::u16_le(7, &mut bytes[16..]);
    BinaryWriter::u16_le(23, &mut bytes[18..]);
    for (at, value) in [(20, 32), (24, 36), (28, 68)] {
        BinaryWriter::u32_le(value, &mut bytes[at..]);
    }
    bytes[32..36].copy_from_slice(b"GOOD");
    bytes[48..68].fill(0xee);
    bytes
}
pub fn cpk() -> Vec<u8> {
    let toc = packet(
        b"TOC ",
        table(
            "CpkTocInfo",
            &[
                ("DirName", 10, 0x30, vec![Cell::Text("dir")]),
                (
                    "FileName",
                    10,
                    0x50,
                    vec![Cell::Text("one.txt"), Cell::Text("../two.bin")],
                ),
                ("FileSize", 4, 0x50, vec![Cell::Number(4), Cell::Number(4)]),
                ("ExtractSize", 4, 0x30, vec![Cell::Number(4)]),
                (
                    "FileOffset",
                    6,
                    0x50,
                    vec![Cell::Number(0x400), Cell::Number(0x404)],
                ),
            ],
            2,
        ),
    );
    let head = packet(
        b"CPK ",
        table(
            "CpkHeader",
            &[
                ("ContentOffset", 6, 0x30, vec![Cell::Number(0x800)]),
                ("TocOffset", 6, 0x30, vec![Cell::Number(0x400)]),
                ("Files", 4, 0x30, vec![Cell::Number(2)]),
            ],
            1,
        ),
    );
    let mut bytes = vec![0; 0x808];
    bytes[..head.len()].copy_from_slice(&head);
    bytes[0x400..0x400 + toc.len()].copy_from_slice(&toc);
    bytes[0x800..].copy_from_slice(b"GOODFAIL");
    bytes
}
