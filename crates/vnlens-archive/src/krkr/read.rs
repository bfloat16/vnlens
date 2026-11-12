//! Lazy XP3 segment inflation, filtering at logical offsets, and seekable
//! plaintext cursors. Adler-32 is checked when a complete entry is consumed;
//! backward seeks replay the transform without retaining decoded payloads.

use super::*;
use std::{
    io::{self, Read},
    sync::atomic::{AtomicBool, Ordering},
};
use vnlens_io::{RangeSource, ReadAt, ReplaySource};

#[derive(Debug)]
pub(super) struct Xp3Source {
    pub view: Arc<ArcView>,
    pub segments: Arc<[Segment]>,
    pub filter: Option<Arc<Filter>>,
    pub entry_filter: Option<(u64, u16)>,
    pub xor_hash: Option<u32>,
    pub checksum: Option<u32>,
    pub offset: u64,
}

struct Segments {
    source: Arc<Xp3Source>,
    cancelled: Arc<AtomicBool>,
    index: usize,
    part: Option<Box<dyn Read + Send>>,
    position: u64,
    part_position: u64,
    checksum: adler32::Adler32,
}

impl Segments {
    fn new(source: Arc<Xp3Source>, cancelled: Arc<AtomicBool>) -> Self {
        Self {
            source,
            cancelled,
            index: 0,
            part: None,
            position: 0,
            part_position: 0,
            checksum: adler32::Adler32::default(),
        }
    }
}

impl Read for Segments {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let Some(segment) = self.source.segments.get(self.index) else {
                if self
                    .source
                    .checksum
                    .is_some_and(|expected| self.checksum.checksum() != expected)
                {
                    return Err(io::Error::other(corrupt(
                        self.source.offset,
                        "XP3 plaintext checksum mismatch",
                    )));
                }
                return Ok(0);
            };
            if self.part.is_none() {
                let source = Arc::new(RangeSource::new(
                    self.source.view.clone(),
                    segment.offset,
                    segment.stored,
                )?);
                let reader = source.reader(self.cancelled.clone())?;
                self.part = Some(if segment.compressed {
                    Box::new(zlib::decoder(reader))
                } else {
                    Box::new(reader)
                });
            }
            let Some(part) = self.part.as_mut() else {
                return Err(io::Error::other("XP3 segment reader is unavailable"));
            };
            let read = part.read(buffer)?;
            if read == 0 {
                if self.part_position != segment.size {
                    return Err(io::Error::other(corrupt(
                        segment.offset,
                        "XP3 decoded segment length mismatch",
                    )));
                }
                self.index += 1;
                self.part = None;
                self.part_position = 0;
                continue;
            }
            self.part_position = self.part_position.checked_add(read as u64).ok_or_else(|| {
                io::Error::other(corrupt(segment.offset, "XP3 decoded segment size overflow"))
            })?;
            if self.part_position > segment.size {
                return Err(io::Error::other(corrupt(
                    segment.offset,
                    "XP3 decoded segment exceeds size",
                )));
            }
            let bytes = &mut buffer[..read];
            apply_filter(
                self.source.filter.as_deref(),
                self.source.entry_filter,
                self.source.xor_hash,
                self.position,
                bytes,
            );
            self.checksum.update(bytes);
            self.position += read as u64;
            return Ok(read);
        }
    }
}

fn apply_filter(
    filter: Option<&Filter>,
    entry_filter: Option<(u64, u16)>,
    xor_hash: Option<u32>,
    offset: u64,
    bytes: &mut [u8],
) {
    if let (Some(filter), Some((key, flags))) = (filter, entry_filter) {
        filter.apply_entry(key, flags, offset, bytes);
    } else if let Some(hash) = xor_hash {
        vnlens_crypto::cipher::xp3::xor31(hash, offset, bytes);
    }
}

impl Xp3Archive {
    pub(super) fn apply_filter(&self, record: &Record, offset: u64, bytes: &mut [u8]) {
        let xor_hash = (self.xor31 && record.flags & 0x8000_0000 != 0)
            .then_some(record.adler)
            .flatten();
        apply_filter(
            self.filter.as_deref(),
            record.filter,
            xor_hash,
            offset,
            bytes,
        );
    }

    pub(super) fn source(&self, entry: &Entry) -> Result<Arc<ReplaySource>> {
        let record = self.record(entry)?;
        let source = Arc::new(Xp3Source {
            view: self.view.clone(),
            segments: record.segments.clone().into(),
            filter: self.filter.clone(),
            entry_filter: record.filter,
            xor_hash: (self.xor31 && record.flags & 0x8000_0000 != 0)
                .then_some(record.adler)
                .flatten(),
            checksum: record.adler,
            offset: entry.offset,
        });
        let factory = Arc::new(move |cancelled| -> io::Result<Box<dyn Read + Send>> {
            Ok(Box::new(Segments::new(source.clone(), cancelled)))
        });
        Ok(Arc::new(ReplaySource::new(factory, record.size)?))
    }

    pub(super) fn read_cancellable(&self, entry: &Entry, cancel: &AtomicBool) -> Result<Vec<u8>> {
        let source = self.source(entry)?;
        let capacity = usize::try_from(source.len())
            .map_err(|_| corrupt(entry.offset, "XP3 size does not fit memory"))?;
        let mut out = Vec::with_capacity(capacity);
        let mut reader = source.reader(Arc::new(AtomicBool::new(false)))?;
        let mut block = [0; 65536];
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            let read = reader.read(&mut block).map_err(|error| {
                if error.get_ref().is_some_and(|cause| cause.is::<Error>()) {
                    if let Some(cause) = error
                        .into_inner()
                        .and_then(|cause| cause.downcast::<Error>().ok())
                    {
                        return *cause;
                    }
                    return Error::Io(io::Error::other("XP3 read failed"));
                }
                Error::Io(error)
            })?;
            if read == 0 {
                return Ok(out);
            }
            out.extend_from_slice(&block[..read]);
        }
    }
}
