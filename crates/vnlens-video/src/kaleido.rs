//! Kaleido MkvFileReader::Read (sub_1400F6A70) XORs each byte using its
//! absolute file offset modulo 4096. sub_1400F62B0 seeds MT19937 from the
//! MD5 of base + ASCII-lowercase basename (sub_1400F6BA0). No MDF header.
use crate::{VideoDecoder, VideoFormat, VideoRegistration, decoder::FfmpegVideo};
use std::{
    borrow::Cow,
    fmt, io,
    sync::{Arc, atomic::AtomicBool},
};
use vnlens_core::{ArchiveOptions, Error, Format, Result};
use vnlens_crypto::cipher::{mdf::MdfStream, xor};
use vnlens_io::{BinaryIo, ReadAt};
const PERIOD: usize = 4096;
#[derive(Debug, Default)]
struct Kaleido;
impl Format for Kaleido {
    fn tag(&self) -> &'static str {
        "webm/kaleido"
    }
    fn signatures(&self) -> &'static [u32] {
        &[0]
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["webm"]
    }
    fn description(&self) -> &'static str {
        "Kaleido encrypted WebM"
    }
}
impl VideoFormat for Kaleido {
    fn decode_source(
        &self,
        source: Arc<dyn ReadAt>,
        name: &str,
        options: &ArchiveOptions,
    ) -> Result<Arc<dyn ReadAt>> {
        let head = source.read_at(0, 4)?;
        if head.as_ref() == [0x1a, 0x45, 0xdf, 0xa3] {
            return Ok(source);
        }
        let base = options.keys.get("kaleido_movie").ok_or_else(|| {
            Error::UnknownScheme(Some("Missing Kaleido movie cipher parameters".into()))
        })?;
        let base = std::str::from_utf8(base.bytes()).map_err(|_| {
            Error::UnknownScheme(Some("Invalid Kaleido movie parameter encoding".into()))
        })?;
        let name = name
            .rsplit(['/', char::from(92)])
            .next()
            .unwrap_or(name)
            .to_ascii_lowercase();
        let mut key = [0; PERIOD];
        MdfStream::new(&format!("{base}{name}"), None).apply(&mut key);
        let decoded = MovieSource { source, key };
        if decoded.read_at(0, 4)?.as_ref() != [0x1a, 0x45, 0xdf, 0xa3] {
            return Err(Error::Corrupt {
                offset: 0,
                reason: "Kaleido movie does not decode to an EBML header".into(),
            });
        }
        Ok(Arc::new(decoded))
    }
    fn open(
        &self,
        source: Arc<dyn ReadAt>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Box<dyn VideoDecoder>> {
        FfmpegVideo::open(source, Some("movie.webm"), cancelled)?
            .map(|video| Box::new(video) as Box<dyn VideoDecoder>)
            .ok_or(Error::InvalidFormat)
    }
}
vnlens_core::inventory::submit! {VideoRegistration(||Box::new(Kaleido))}
struct MovieSource {
    source: Arc<dyn ReadAt>,
    key: [u8; PERIOD],
}
impl fmt::Debug for MovieSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KaleidoMovieSource")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}
impl ReadAt for MovieSource {
    fn len(&self) -> u64 {
        self.source.len()
    }
    fn read_at(&self, offset: u64, size: usize) -> io::Result<Cow<'_, [u8]>> {
        if offset > self.len() || size as u64 > self.len() - offset {
            return Err(BinaryIo::unexpected_eof(
                "Kaleido movie read exceeds source",
            ));
        }
        let mut bytes = self.source.read_at(offset, size)?;
        let mut position = (offset % PERIOD as u64) as usize;
        let mut remaining = bytes.to_mut().as_mut_slice();
        while !remaining.is_empty() {
            let count = remaining.len().min(PERIOD - position);
            xor::apply(
                &mut remaining[..count],
                &self.key[position..position + count],
            )
            .map_err(io::Error::other)?;
            remaining = &mut remaining[count..];
            position = 0;
        }
        Ok(bytes)
    }
}

#[cfg(test)]
#[path = "../tests/kaleido.rs"]
mod tests;
