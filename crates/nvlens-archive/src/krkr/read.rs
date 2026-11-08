//! Lazy XP3 segment inflation and filtering at logical offsets. The engine
//! selects the Rust filter; protected entries require its parameters at mount.
use super::*;
use std::{
    io::Read,
    sync::atomic::{AtomicBool, Ordering},
};
impl Xp3Archive {
    pub(super) fn apply_filter(&self, record: &Record, offset: u64, bytes: &mut [u8]) {
        if let (Some((key, flag)), Some(filter)) = (record.filter, &self.filter) {
            filter.apply_entry(key, flag, offset, bytes);
        } else if self.xor31 && record.flags & 0x8000_0000 != 0 {
            // The required checksum field was validated when the index opened.
            if let Some(hash) = record.adler {
                nvlens_crypto::cipher::xp3::xor31(hash, offset, bytes);
            }
        }
    }
    pub(super) fn read_cancellable(&self, entry: &Entry, cancel: &AtomicBool) -> Result<Vec<u8>> {
        let record = self.record(entry)?;
        let mut out = Vec::new();
        for segment in &record.segments {
            let raw = self.view.slice(segment.offset, segment.stored)?;
            let mut reader: Box<dyn Read + '_> = if segment.compressed {
                Box::new(zlib::decoder(raw))
            } else {
                Box::new(raw)
            };
            let start = out.len();
            let mut block = [0; 65536];
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return Err(Error::Cancelled);
                }
                let read = reader.read(&mut block)?;
                if read == 0 {
                    break;
                }
                if (out.len() - start) as u64 + read as u64 > segment.size {
                    return Err(corrupt(segment.offset, "XP3 decoded segment exceeds size"));
                }
                self.apply_filter(record, out.len() as u64, &mut block[..read]);
                out.extend_from_slice(&block[..read]);
            }
            if (out.len() - start) as u64 != segment.size {
                return Err(corrupt(
                    segment.offset,
                    "XP3 decoded segment length mismatch",
                ));
            }
        }
        if record
            .adler
            .is_some_and(|sum| adler32::checksum(&out) != sum)
        {
            return Err(corrupt(entry.offset, "XP3 plaintext checksum mismatch"));
        }
        Ok(out)
    }
}
