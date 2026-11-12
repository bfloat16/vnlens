//! A borrowed or owned PSB view that decrypts only requested ranges. The
//! XorShift state continues from the header in full-encryption mode; bodies
//! stop at OffsetChunkOffsets (PsbFile.WriteEncodeBody), before chunk tables.
//! In v4 that range can also include extra-resource payloads.
use super::header::validate_header;
use super::{ParseOptions, PsbEncryption, PsbHeader, corrupt};
use std::{
    borrow::Cow,
    io,
    ops::Range,
    sync::{Arc, Mutex},
};
use vnlens_core::{Error, Result};
use vnlens_crypto::cipher::psb_stream::PsbStream;
use vnlens_io::{BinaryIo, BinarySourceReader, ReadAt};

pub(super) struct PsbSource<'a> {
    data: Source<'a>,
    range: Range<u64>,
    initial: PsbStream,
    state: Mutex<(PsbStream, u64)>,
    cancelled: Option<&'a std::sync::atomic::AtomicBool>,
}

enum Source<'a> {
    Borrowed(&'a dyn ReadAt),
    Shared(Arc<dyn ReadAt>),
}
impl Source<'_> {
    fn get(&self) -> &dyn ReadAt {
        match self {
            Self::Borrowed(data) => *data,
            Self::Shared(data) => &**data,
        }
    }
}

/// Buffers index reads before the first declared chunk-data area. A window
/// never crosses into a resource, including v4 extra chunks. Mapped sources
/// keep borrowed windows; transformed sources retain one decoded window.
pub(super) struct IndexSource<'a> {
    data: &'a dyn ReadAt,
    end: u64,
    window: Mutex<(u64, Cow<'a, [u8]>)>,
    cancelled: Option<&'a std::sync::atomic::AtomicBool>,
}

impl<'a> IndexSource<'a> {
    pub(super) fn new(
        data: &'a dyn ReadAt,
        header: &PsbHeader,
        cancelled: Option<&'a std::sync::atomic::AtomicBool>,
    ) -> Self {
        let end = u64::from(header.offset_chunk_data)
            .min(header.offset_extra_chunk_data.map_or(u64::MAX, u64::from));
        Self {
            data,
            end,
            window: Mutex::new((0, Cow::Borrowed(&[]))),
            cancelled,
        }
    }
}

impl ReadAt for IndexSource<'_> {
    fn len(&self) -> u64 {
        self.data.len()
    }

    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        check_read_cancelled(self.cancelled)?;
        let end = offset
            .checked_add(size as u64)
            .ok_or_else(|| BinaryIo::unexpected_eof("PSB index range overflow"))?;
        if size == 0 || end > self.end {
            return self.data.read_at(offset, size);
        }
        let mut window = self
            .window
            .lock()
            .map_err(|_| io::Error::other("PSB index window lock poisoned"))?;
        if offset < window.0 || end - window.0 > window.1.len() as u64 {
            let size = usize::try_from((self.end - offset).min(size.max(65536) as u64))
                .map_err(io::Error::other)?;
            let bytes = self.data.read_at(offset, size)?;
            if bytes.len() != size {
                return Err(BinaryIo::unexpected_eof("short PSB index window"));
            }
            *window = (offset, bytes);
        }
        let first = usize::try_from(offset - window.0).map_err(io::Error::other)?;
        let last = first + size;
        match &window.1 {
            Cow::Borrowed(bytes) => {
                let bytes = *bytes;
                Ok(Cow::Borrowed(&bytes[first..last]))
            }
            Cow::Owned(bytes) => Ok(Cow::Owned(bytes[first..last].to_vec())),
        }
    }
}

fn check_read_cancelled(cancelled: Option<&std::sync::atomic::AtomicBool>) -> io::Result<()> {
    if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "PSB parsing was cancelled",
        ));
    }
    Ok(())
}

impl<'a> PsbSource<'a> {
    pub(super) fn new(
        data: &'a dyn ReadAt,
        options: ParseOptions<'a>,
    ) -> Result<(Self, PsbHeader, PsbEncryption)> {
        let plain = PsbHeader::read(data, None)?;
        let header_encrypted = match options.encryption {
            PsbEncryption::Auto => {
                validate_header(&plain, data.len()).is_err()
                    && (plain.flags & 1 != 0 || options.psb_key.is_some())
            }
            PsbEncryption::Header | PsbEncryption::Full => true,
            _ => false,
        };
        let mut cipher = PsbStream::new(options.psb_key.unwrap_or_default());
        let header = if header_encrypted {
            require_key(options)?;
            PsbHeader::read(data, Some(&mut cipher))?
        } else {
            plain
        };
        validate_header(&header, data.len())?;
        let start = u64::from(if header.version == 1 {
            header.header_length
        } else {
            header.offset_names
        });
        let body_encrypted = match options.encryption {
            PsbEncryption::Auto => !has_array_prefix(data, start)?,
            PsbEncryption::Body | PsbEncryption::Full => true,
            _ => false,
        };
        let range = if body_encrypted {
            require_key(options)?;
            let end = u64::from(header.offset_chunk_offsets);
            if end < start {
                return Err(corrupt(start, "PSB encrypted metadata range is reversed"));
            }
            start..end
        } else {
            0..0
        };
        let encryption = match (header_encrypted, body_encrypted) {
            (true, true) => PsbEncryption::Full,
            (true, false) => PsbEncryption::Header,
            (false, true) => PsbEncryption::Body,
            (false, false) => PsbEncryption::None,
        };
        if header.version == 4 && header.checksum_valid() == Some(false) {
            return Err(corrupt(40, "PSB v4 header checksum mismatch"));
        }
        Ok((
            Self {
                data: Source::Borrowed(data),
                range: range.clone(),
                initial: cipher.clone(),
                state: Mutex::new((cipher, range.start)),
                cancelled: options.cancelled,
            },
            header,
            encryption,
        ))
    }

    pub(super) fn into_shared(self, data: Arc<dyn ReadAt>) -> PsbSource<'static> {
        PsbSource {
            data: Source::Shared(data),
            range: self.range,
            initial: self.initial,
            state: self.state,
            cancelled: None,
        }
    }
}

fn require_key(options: ParseOptions<'_>) -> Result<()> {
    if options.psb_key.is_none() {
        return Err(Error::UnknownScheme(Some("PSB stream key".into())));
    }
    Ok(())
}

// Select a variant from the serialized name-array header, before tree parsing.
// The explicit encryption option handles prefixes that are ambiguous by chance.
fn has_array_prefix(data: &dyn ReadAt, offset: u64) -> Result<bool> {
    let offset =
        usize::try_from(offset).map_err(|_| corrupt(offset, "PSB offset does not fit usize"))?;
    let mut reader = BinarySourceReader::new_at(data, offset)?;
    let tag = reader.read_u8()?;
    if !(0x0d..=0x14).contains(&tag) {
        return Ok(false);
    }
    let count = reader.read_compact_u64_le(usize::from(tag - 0x0c))?;
    let tag = reader.read_u8()?;
    if !(0x0d..=0x14).contains(&tag) {
        return Ok(false);
    }
    Ok(count
        .checked_mul(u64::from(tag - 0x0c))
        .is_some_and(|size| size <= reader.remaining()))
}

impl ReadAt for PsbSource<'_> {
    fn len(&self) -> u64 {
        self.data.get().len()
    }

    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        check_read_cancelled(self.cancelled)?;
        let end = offset
            .checked_add(size as u64)
            .filter(|&end| end <= self.len())
            .ok_or_else(|| BinaryIo::unexpected_eof("PSB read exceeds source"))?;
        let mut bytes = self.data.get().read_at(offset, size)?;
        let start = offset.max(self.range.start);
        let finish = end.min(self.range.end);
        if start >= finish {
            return Ok(bytes);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("PSB cipher lock poisoned"))?;
        if start < state.1 {
            *state = (self.initial.clone(), self.range.start);
        }
        let skip = start - state.1;
        state.0.skip(skip);
        let first = usize::try_from(start - offset).map_err(io::Error::other)?;
        let last = usize::try_from(finish - offset).map_err(io::Error::other)?;
        state.0.apply(&mut bytes.to_mut()[first..last]);
        state.1 = finish;
        Ok(bytes)
    }
}
