//! USM/CRID framing: BE chunk size excludes the first eight bytes; payload
//! offset is relative to byte eight, padding follows the payload. Metadata
//! chunks contain @UTF. Opening reads the initial metadata section only.
use super::{add, bounds, corrupt, range, utf::Table};
use std::{borrow::Cow, io, sync::Arc};
use vnlens_core::{Error, Result};
use vnlens_io::{BinaryReader, ReadAt};

#[derive(Clone, Debug)]
pub struct Chunk {
    pub id: [u8; 4],
    pub offset: u64,
    pub size: u64,
    pub payload_offset: u64,
    pub payload_size: u64,
    pub channel: u8,
    pub kind: u8,
    pub frame_time: u32,
    pub frame_rate: u32,
}

#[derive(Debug)]
pub struct StreamHeader {
    pub chunk: Chunk,
    pub table: Arc<Table>,
}

/// Native VIDEO_SEEKINFO record. Offsets address the original USM, and frame
/// numbers are presentation positions, not demuxer packet timestamps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeekPoint {
    pub offset: u64,
    pub frame: u64,
    pub skip: u64,
}

pub struct Usm {
    pub headers: Vec<StreamHeader>,
    pub first_data: u64,
    source: Arc<dyn ReadAt>,
}
impl std::fmt::Debug for Usm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Usm")
            .field("headers", &self.headers)
            .field("first_data", &self.first_data)
            .finish_non_exhaustive()
    }
}
impl Usm {
    /// Indexes the directory and stream headers preceding the first payload.
    pub fn open(source: Arc<dyn ReadAt>) -> Result<Self> {
        if source.read_at(0, 4)?.as_ref() != b"CRID" {
            return Err(Error::InvalidFormat);
        }
        let mut headers = Vec::new();
        let mut offset = 0;
        while offset < source.len() {
            let chunk = chunk(source.as_ref(), offset)?;
            if chunk.kind == 0 && &chunk.id != b"CRID" {
                break;
            }
            if chunk.kind == 1 || chunk.kind == 3 || &chunk.id == b"CRID" {
                let table = Arc::new(Table::open(range(
                    source.clone(),
                    chunk.payload_offset,
                    chunk.payload_size,
                )?)?);
                headers.push(StreamHeader {
                    chunk: chunk.clone(),
                    table,
                });
            }
            offset = add(offset, chunk.size)?;
        }
        Ok(Self {
            headers,
            first_data: offset,
            source,
        })
    }

    pub fn chunk(&self, offset: u64) -> Result<Chunk> {
        chunk(self.source.as_ref(), offset)
    }
    pub fn payload(&self, chunk: &Chunk) -> Result<Arc<dyn ReadAt>> {
        range(
            self.source.clone(),
            chunk.payload_offset,
            chunk.payload_size,
        )
    }

    /// Reads the native seek index without visiting encoded movie payloads.
    /// Matches criMvPly_CalcSeekPosition's ofs_frmid / ofs_byte selection;
    /// decoder-specific preroll (num_skip) is retained for the caller.
    pub fn video_seek_points(&self, channel: u8) -> Result<Vec<SeekPoint>> {
        let mut points = Vec::new();
        for header in &self.headers {
            if header.chunk.id != *b"@SFV"
                || header.chunk.channel != channel
                || header.chunk.kind != 3
                || header.table.name != "VIDEO_SEEKINFO"
            {
                continue;
            }
            for row in 0..header.table.row_count {
                let field = |name| {
                    header.table.number(row, name)?.ok_or_else(|| {
                        corrupt(
                            header.chunk.offset,
                            format!("Missing USM seek field {name}"),
                        )
                    })
                };
                let point = SeekPoint {
                    offset: field("ofs_byte")?,
                    frame: field("ofs_frmid")?,
                    skip: header.table.number(row, "num_skip")?.unwrap_or(0),
                };
                bounds(self.source.as_ref(), point.offset, 32)?;
                if point.offset < self.first_data
                    || points.last().is_some_and(|last: &SeekPoint| {
                        last.frame > point.frame || last.offset > point.offset
                    })
                {
                    return Err(corrupt(
                        header.chunk.offset,
                        "Invalid USM seek index ordering",
                    ));
                }
                points.push(point);
            }
        }
        Ok(points)
    }

    /// Presents the original video metadata followed by a native seek block.
    /// Other stream headers are omitted: midstream ADX packets have no codec
    /// header and must not be probed as the start of an audio stream. The
    /// caller keeps the original movie's metadata and presentation clock.
    /// Encoded payloads remain borrowed ranges of the original source.
    pub fn video_seek_source(&self, channel: u8, offset: u64) -> Result<Arc<dyn ReadAt>> {
        let first = self.chunk(offset)?;
        if first.id != *b"@SFV" || first.channel != channel || first.kind != 0 {
            return Err(corrupt(
                offset,
                "USM seek offset does not address a video data chunk",
            ));
        }
        let mut ranges = Vec::new();
        let mut size = 0;
        let mut at = 0;
        while at < self.first_data {
            let chunk = self.chunk(at)?;
            if chunk.id == *b"CRID" || (chunk.id == *b"@SFV" && chunk.channel == channel) {
                ranges.push((size, at, chunk.size));
                size = add(size, chunk.size)?;
            }
            at = add(at, chunk.size)?;
        }
        ranges.push((size, offset, self.source.len() - offset));
        size = add(size, self.source.len() - offset)?;
        Ok(Arc::new(SeekSource {
            source: self.source.clone(),
            ranges,
            size,
        }))
    }
}

struct SeekSource {
    source: Arc<dyn ReadAt>,
    // (virtual offset, original offset, length), all in source order.
    ranges: Vec<(u64, u64, u64)>,
    size: u64,
}
impl ReadAt for SeekSource {
    fn len(&self) -> u64 {
        self.size
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        if offset > self.size || size as u64 > self.size - offset {
            return Err(vnlens_io::BinaryIo::unexpected_eof(
                "USM seek view range exceeds source",
            ));
        }
        if size == 0 {
            return Ok(Cow::Borrowed(&[]));
        }
        let index = self
            .ranges
            .partition_point(|&(start, _, _)| start <= offset)
            - 1;
        let (start, original, length) = self.ranges[index];
        let relative = offset - start;
        if size as u64 <= length - relative {
            return self.source.read_at(original + relative, size);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(io::Error::other)?;
        let mut position = offset;
        for &(start, original, length) in &self.ranges[index..] {
            let relative = position - start;
            let count = (length - relative).min((size - bytes.len()) as u64) as usize;
            bytes.extend_from_slice(&self.source.read_at(original + relative, count)?);
            position += count as u64;
            if bytes.len() == size {
                break;
            }
        }
        Ok(Cow::Owned(bytes))
    }
}

pub fn chunk(source: &dyn ReadAt, offset: u64) -> Result<Chunk> {
    let header = source.read_at(offset, 32)?;
    let size = add(8, u64::from(BinaryReader::u32_be(&header[4..8])))?;
    let payload = add(8, u64::from(header[9]))?;
    let padding = u64::from(BinaryReader::u16_be(&header[10..12]));
    if size < 32 || payload < 32 || payload > size || padding > size - payload {
        return Err(corrupt(offset, "Invalid USM chunk/payload bounds"));
    }
    bounds(source, offset, size)?;
    Ok(Chunk {
        id: header[..4].try_into().map_err(|_| Error::InvalidFormat)?,
        offset,
        size,
        payload_offset: add(offset, payload)?,
        payload_size: size - payload - padding,
        channel: header[12],
        kind: header[15],
        frame_time: BinaryReader::u32_be(&header[16..20]),
        frame_rate: BinaryReader::u32_be(&header[20..24]),
    })
}

#[cfg(test)]
#[path = "../../tests/criware/usm.rs"]
mod tests;
