//! MDB sheets from misc/game.c::db_load/db_set: LE metadata length, sheet
//! name offset/column count and 8-byte column descriptors, data length/data,
//! text length/text; a zero metadata length terminates the file. Text offsets
//! are relative to the sheet's CP932 pool. Rows follow declared column widths.
use super::*;
use crate::ir::{ArgName as A, Qualifier as Q};

pub(super) fn parse(data: &[u8]) -> Result<Script> {
    let mut r = BinaryReader::new_at(data, 4)?;
    let mut out = script(data, "mdb/escude", 1);
    record(
        &mut out,
        0,
        4,
        Q::ScriptMetadata,
        vec![arg(A::Signature, 0, 4, Value::Bytes(data[..4].to_vec()))],
    );
    loop {
        let start = r.position();
        let metadata_size = r.read_u32_le()? as usize;
        if metadata_size == 0 {
            let mut args = vec![number(A::Terminator(0), start, 0)];
            if r.remaining() != 0 {
                let at = r.position();
                args.push(arg(
                    A::Padding,
                    at,
                    r.remaining(),
                    Value::Bytes(r.read_bytes(r.remaining())?.to_vec()),
                ));
            }
            record(&mut out, start, r.position() - start, Q::BlockEnd, args);
            break;
        }
        let meta_start = r.position();
        let mut meta = BinaryReader::new(r.read_bytes(metadata_size)?);
        let name = meta.read_u32_le()?;
        let columns = meta.read_u32_le()?;
        let mut definitions = Vec::new();
        let mut width = 0usize;
        for _ in 0..columns {
            let at = meta_start + meta.position();
            let kind = meta.read_u16_le()?;
            let size = meta.read_u16_le()?;
            let name = meta.read_u32_le()?;
            width = width
                .checked_add(usize::from(size))
                .ok_or_else(|| bad(at, "MDB row size overflow"))?;
            definitions.push((at, kind, size, name));
        }
        let data_size_at = r.position();
        let data_size = r.read_u32_le()? as usize;
        let rows_at = r.position();
        let rows = r.read_bytes(data_size)?;
        let text_size_at = r.position();
        let text_size = r.read_u32_le()? as usize;
        let pool_at = r.position();
        let pool = r.read_bytes(text_size)?;
        if (width == 0 && data_size != 0) || (width != 0 && !data_size.is_multiple_of(width)) {
            return Err(bad(rows_at, "MDB data does not contain complete rows"));
        }
        let title = text(cstring(pool, name as usize)?);
        let mut fields = Vec::new();
        for (index, &(at, kind, size, name)) in definitions.iter().enumerate() {
            let field = vec![
                arg(A::Type, at, 2, Value::Unsigned(u64::from(kind))),
                arg(A::ByteCount, at + 2, 2, Value::Unsigned(u64::from(size))),
                number(A::DataOffset, at + 4, name),
                arg(
                    A::Name,
                    pool_at + name as usize,
                    cstring(pool, name as usize)?.len(),
                    text(cstring(pool, name as usize)?),
                ),
            ];
            fields.push(arg(A::Column(index as u64), at, 8, Value::Group(field)));
        }
        let mut values = Vec::new();
        for (row_index, row) in rows.chunks(width.max(1)).enumerate() {
            let row_at = rows_at + row_index * width;
            let mut cells = BinaryReader::new(row);
            let mut fields = Vec::new();
            for (column, &(_, kind, size, name)) in definitions.iter().enumerate() {
                let at = row_at + cells.position();
                let bytes = cells.read_bytes(usize::from(size))?;
                let value = match (kind, size) {
                    (1, 1) => Value::Unsigned(u64::from(bytes[0])),
                    (1, 2) => Value::Integer(i64::from(BinaryReader::u16_le(bytes) as i16)),
                    (1, 4) => Value::Integer(i64::from(BinaryReader::u32_le(bytes) as i32)),
                    (2, 4) => Value::Float32Bits(BinaryReader::u32_le(bytes)),
                    (3, _) => text(bytes.split(|&b| b == 0).next().unwrap_or_default()),
                    (4, 4) => {
                        let offset = BinaryReader::u32_le(bytes);
                        let value = cstring(pool, offset as usize)?;
                        Value::Group(vec![
                            number(A::DataOffset, at, offset),
                            arg(A::Text, pool_at + offset as usize, value.len(), text(value)),
                        ])
                    }
                    _ => Value::Bytes(bytes.to_vec()),
                };
                let mut field = arg(A::Column(column as u64), at, usize::from(size), value);
                if let Value::Text(name) = text(cstring(pool, name as usize)?) {
                    field.native_name = Some(name);
                }
                fields.push(field);
            }
            values.push(arg(
                A::Row(row_index as u64),
                row_at,
                width,
                Value::Group(fields),
            ));
        }
        let mut args = vec![
            number(A::ByteCount, start, metadata_size as u32),
            number(A::DataOffset, meta_start, name),
            arg(
                A::Name,
                pool_at + name as usize,
                cstring(pool, name as usize)?.len(),
                title,
            ),
            number(A::Count, meta_start + 4, columns),
            arg(
                A::Metadata,
                meta_start + 8,
                definitions.len() * 8,
                Value::Group(fields),
            ),
            number(A::ByteCount, data_size_at, data_size as u32),
            arg(A::Rows, rows_at, data_size, Value::Group(values)),
            number(A::ByteCount, text_size_at, text_size as u32),
            arg(A::Data, pool_at, text_size, Value::Bytes(pool.to_vec())),
        ];
        if meta.remaining() != 0 {
            let at = meta_start + meta.position();
            args.push(arg(
                A::Padding,
                at,
                meta.remaining(),
                Value::Bytes(meta.read_bytes(meta.remaining())?.to_vec()),
            ));
        }
        record(&mut out, start, r.position() - start, Q::DataTable, args);
    }
    Ok(out)
}
