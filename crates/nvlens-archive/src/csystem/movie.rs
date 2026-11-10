//! Independent random-access movie windows. The stored leading u32 belongs
//! to C,system; sparse payload XOR uses offsets after that word.
use super::*;

#[derive(Debug)]
pub(super) struct Movie {
    source: RangeSource,
}
impl Movie {
    pub fn open(view: Arc<ArcView>, entry: &Entry) -> Result<Arc<dyn ReadAt>> {
        let size = entry.size.checked_sub(4).ok_or_else(|| {
            nvlens_io::BinaryIo::unexpected_eof("Truncated C,system movie header")
        })?;
        Ok(Arc::new(Self {
            source: RangeSource::new(view, entry.offset + 4, size)?,
        }))
    }
}
impl ReadAt for Movie {
    fn len(&self) -> u64 {
        self.source.len()
    }
    fn read_at(&self, offset: u64, size: usize) -> std::io::Result<Cow<'_, [u8]>> {
        let mut data = self.source.read_at(offset, size)?;
        if offset.saturating_add(size as u64) > 0x800 {
            nvlens_crypto::cipher::csystem::movie(data.to_mut(), offset);
        }
        Ok(data)
    }
}
